#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("lab-e2e-review.py")
SPEC = importlib.util.spec_from_file_location("lab_e2e_review", SCRIPT)
review = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(review)


class LabE2EReviewTests(unittest.TestCase):
    def test_allows_expected_staged_placeholders(self) -> None:
        text = "aipostex openai-compat --target http://127.0.0.1:4000 validate-inference --model <model>"
        self.assertEqual(review.find_guidance_issues(text), {})

    def test_flags_stale_guidance_and_unexpected_placeholders(self) -> None:
        text = "aipostex openai-compat --target http://127.0.0.1:4000 auth-sweep --token sk-test\nnext: aipostex demo --value <oops>"
        issues = review.find_guidance_issues(text)
        self.assertEqual(issues["stale openai-compat --token guidance"], 1)
        self.assertEqual(issues["unexpected unresolved placeholder"], 1)

    def test_reports_coverage_events(self) -> None:
        text = "coverage_expanded=true skip_reason=http-template-incompatible"
        events = review.find_coverage_events(text)
        self.assertEqual(events["ambiguous services expanded"], 1)
        self.assertEqual(events["non-http services skipped for http templates"], 1)


if __name__ == "__main__":
    unittest.main()
