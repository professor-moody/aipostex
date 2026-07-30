# engagement merge

Combine multiple engagement JSON or JSONL files into a single output for scoring.

## Synopsis

```bash
aipostex engagement merge [file1.json] [file2.json] ... [flags]
```

## Description

The `engagement merge` command reads multiple aipostex engagement JSON documents or JSONL finding streams and combines them into a single unified engagement document. Duplicate findings are removed based on a content hash of the target, title, and evidence fields.

This is useful when running separate module commands (e.g., `ollama prompts`, `vectordb search-sensitive`, `ray jobs`) and needing to combine results into one file for scoring or reporting.

## Flags

| Flag | Description |
|---|---|
| `--output`, `-o` | Output file path (default: stdout) |

Only `--output` applies to this command.

## Deduplication

Findings are deduplicated by SHA-256 hash of `target + title + evidence`. When duplicates exist, the earliest finding (by timestamp) is kept.

## Examples

```bash
# Merge three result files into one
aipostex engagement merge ollama.json vectordb.json ray.json -o combined.json

# Merge all JSON files in a directory
aipostex engagement merge results/*.json -o assessment.json

# Merge and output to stdout
aipostex engagement merge scan-results.json mlflow-results.json
```

## Workflow

```
Run individual module commands with --format json or --format jsonl --output <file>
  → aipostex engagement merge <file1> <file2> ... -o combined.json
    → aipostex report summary combined.json
```
