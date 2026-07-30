#!/usr/bin/env python3
"""Review aipostex lab verifier logs and JSON outputs.

This is intentionally a script-level helper, not a product CLI command.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


RESULT_RE = re.compile(r"Results:\s*(\d+)\s+passed,\s*(\d+)\s+failed,\s*(\d+)\s+skipped", re.I)
SYNTHETIC_RESULT_RE = re.compile(r"\bresults\s+pass=(\d+)\s+fail=(\d+)\s+skip=(\d+)", re.I)
FAIL_RE = re.compile(r"(?:\[[x✗]\]|\[FAIL\])\s*(.*)", re.I)
COVERAGE_WARNING_RE = re.compile(
    r"(?:Warning:\s*)?.*(?:incomplete coverage|assessment incomplete|partial failures?:\s*[1-9]\d*).*",
    re.I,
)
BACKEND_CLASSES = {
    "backend-dependency-missing",
    "backend-config-error",
    "model-route-error",
    "auth-rejected",
    "network-error",
    "server-error",
    "unknown",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Review aipostex lab e2e logs and JSON output")
    parser.add_argument("paths", nargs="+", help="Verifier log files, JSON files, or directories")
    parser.add_argument("-o", "--output", help="Write Markdown report to this path")
    args = parser.parse_args()

    paths = [Path(p) for p in args.paths]
    logs = [p for p in expand_paths(paths) if p.suffix.lower() in {".log", ".txt", ".out", ".stderr"}]
    json_files = [p for p in expand_paths(paths) if p.suffix.lower() in {".json", ".jsonl"}]

    report = build_report(logs, json_files)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


def expand_paths(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            out.extend(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            out.append(path)
    return out


def build_report(logs: list[Path], json_files: list[Path]) -> str:
    totals = Counter()
    failed_checks: list[str] = []
    coverage_warnings: list[str] = []
    stale_guidance = Counter()
    backend_classes = Counter()
    coverage_events = Counter()
    finding_count = 0
    landed = Counter()
    severity = Counter()

    for log in logs:
        text = log.read_text(encoding="utf-8", errors="replace")
        for match in RESULT_RE.finditer(strip_ansi(text)):
            totals["passed"] += int(match.group(1))
            totals["failed"] += int(match.group(2))
            totals["skipped"] += int(match.group(3))
        for match in SYNTHETIC_RESULT_RE.finditer(strip_ansi(text)):
            totals["passed"] += int(match.group(1))
            totals["failed"] += int(match.group(2))
            totals["skipped"] += int(match.group(3))
        failed_checks.extend(f"{log.name}: {m.group(1).strip()}" for m in FAIL_RE.finditer(strip_ansi(text)) if m.group(1).strip())
        coverage_warnings.extend(
            f"{log.name}: {m.group(0).strip()}"
            for m in COVERAGE_WARNING_RE.finditer(strip_ansi(text))
            if m.group(0).strip()
        )
        stale_guidance.update(find_guidance_issues(text))
        backend_classes.update(find_backend_classes(text))
        coverage_events.update(find_coverage_events(text))

    for path in json_files:
        for doc in load_json_documents(path):
            findings = extract_findings(doc)
            finding_count += len(findings)
            for finding in findings:
                meta = finding.get("metadata") or {}
                sev = str(finding.get("severity") or "").lower()
                if sev:
                    severity[sev] += 1
                lv = str(meta.get("landed") or "")
                if lv:
                    landed[lv] += 1
                fc = str(meta.get("failure_class") or "")
                if fc:
                    backend_classes[fc] += 1
                attempts = meta.get("model_attempts") or []
                if isinstance(attempts, list):
                    for attempt in attempts:
                        if isinstance(attempt, dict) and attempt.get("failure_class"):
                            backend_classes[str(attempt["failure_class"])] += 1
                stale_guidance.update(find_guidance_issues(guidance_text_from_finding(finding)))
                coverage_events.update(find_coverage_events(json.dumps(finding, sort_keys=True)))

    lines = ["# aipostex Lab E2E Review", ""]
    lines.append(f"- Logs reviewed: {len(logs)}")
    lines.append(f"- JSON files reviewed: {len(json_files)}")
    lines.append(f"- Verifier totals: {totals['passed']} passed, {totals['failed']} failed, {totals['skipped']} skipped")
    lines.append(f"- Findings parsed: {finding_count}")
    lines.append("")
    lines.extend(counter_section("Severity", severity))
    lines.extend(counter_section("Landed", landed))
    lines.extend(counter_section("Backend Failure Classes", backend_classes))
    lines.extend(counter_section("Coverage Expansion / Skips", coverage_events))
    lines.extend(counter_section("Next-Action / Guidance Issues", stale_guidance))
    lines.append("## Failed Checks")
    if failed_checks:
        lines.extend(f"- {item}" for item in failed_checks[:100])
        if len(failed_checks) > 100:
            lines.append(f"- ... {len(failed_checks) - 100} more")
    else:
        lines.append("- None found in reviewed logs.")
    lines.append("")
    lines.append("## Coverage Warnings")
    if coverage_warnings:
        lines.extend(f"- {item}" for item in coverage_warnings[:100])
        if len(coverage_warnings) > 100:
            lines.append(f"- ... {len(coverage_warnings) - 100} more")
    else:
        lines.append("- None found in reviewed logs.")
    lines.append("")
    return "\n".join(lines)


def counter_section(title: str, counter: Counter[str]) -> list[str]:
    lines = [f"## {title}"]
    if not counter:
        lines.append("- None")
    else:
        for key, count in counter.most_common():
            lines.append(f"- {key}: {count}")
    lines.append("")
    return lines


def load_json_documents(path: Path) -> Iterable[Any]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if path.suffix.lower() == ".jsonl":
        docs = []
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError as exc:
                # Do not silently drop malformed output — a truncated/corrupt
                # findings file would otherwise read as a clean "0 findings" run.
                print(f"warning: {path}:{lineno}: skipping malformed JSONL line: {exc}", file=sys.stderr)
        return docs
    try:
        return [json.loads(text)]
    except json.JSONDecodeError as exc:
        print(f"warning: {path}: skipping malformed JSON document: {exc}", file=sys.stderr)
        return []


def extract_findings(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, dict):
        findings = doc.get("findings")
        if isinstance(findings, list):
            return [f for f in findings if isinstance(f, dict)]
        if {"title", "severity", "metadata"} & set(doc.keys()):
            return [doc]
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    return []


def find_guidance_issues(text: str) -> Counter[str]:
    issues = Counter()
    if re.search(r"openai-compat[^\n]*--token|--token[^\n]*openai-compat", text):
        issues["stale openai-compat --token guidance"] += 1
    if re.search(r"aipostex\s+[^\n]*vectordb[^\n]*rag-verify(?![^\n]*--collection)", text):
        issues["rag-verify missing --collection"] += 1
    unexpected = unexpected_placeholders(text)
    if unexpected:
        issues["unexpected unresolved placeholder"] += len(unexpected)
    if "inventory-only" in text and re.search(r"inference (validated|confirmed|capable)", text, re.I):
        issues["inventory-only mixed with inference-confirmed language"] += 1
    return issues


def guidance_text_from_finding(finding: dict[str, Any]) -> str:
    meta = finding.get("metadata") or {}
    lines: list[str] = []
    workflow = meta.get("workflow")
    if isinstance(workflow, dict):
        recs = workflow.get("recommendations")
        if isinstance(recs, list):
            for rec in recs:
                if isinstance(rec, dict) and rec.get("command"):
                    lines.append(str(rec["command"]))
    next_actions = finding.get("next_actions")
    if isinstance(next_actions, list):
        lines.extend(str(value) for value in next_actions)
    return "\n".join(lines)


EXPECTED_STAGED_PLACEHOLDERS = {
    "api-name",
    "artifact-path",
    "collection",
    "entity",
    "experiment-id",
    "file-ref",
    "job-id",
    "kernel-id",
    "model",
    "openai-compatible-target",
    "pipeline-id",
    "project",
    "registered-model",
    "run-id",
    "task-id",
    "training-repo",
    "version",
}


def unexpected_placeholders(text: str) -> list[str]:
    values = []
    for line in guidance_lines(text):
        for match in re.finditer(r"<([^>\n]+)>", line):
            placeholder = match.group(1).strip().lower()
            if placeholder not in EXPECTED_STAGED_PLACEHOLDERS:
                values.append(placeholder)
    return values


def guidance_lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        lower = line.lower()
        if "aipostex" in lower or '"command"' in lower or "next:" in lower:
            yield line


def find_coverage_events(text: str) -> Counter[str]:
    counter = Counter()
    lower = text.lower()
    if "coverage_expanded" in lower or "ambiguous service(s) expanded" in lower:
        counter["ambiguous services expanded"] += lower.count("coverage_expanded") or lower.count("ambiguous service(s) expanded")
    if "http-template-incompatible" in lower or "non-http service identity(s) skipped" in lower:
        counter["non-http services skipped for http templates"] += lower.count("http-template-incompatible") or lower.count("non-http service identity(s) skipped")
    return counter


def find_backend_classes(text: str) -> Counter[str]:
    counter = Counter()
    lower = text.lower()
    for cls in BACKEND_CLASSES:
        if cls == "unknown":
            if re.search(r"failure[_ -]?class[\"':= ]+unknown", lower):
                counter[cls] += 1
            continue
        if cls in lower:
            counter[cls] += lower.count(cls)
    if "botocore" in lower or "missing boto3" in lower:
        counter["backend-dependency-missing"] += 1
    return counter


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


if __name__ == "__main__":
    raise SystemExit(main())
