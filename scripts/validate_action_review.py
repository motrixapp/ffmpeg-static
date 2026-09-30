#!/usr/bin/env python3
"""Require a current, explicit review of the exact Actions used for release."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_workflow_actions import audit_workflow, workflow_paths  # noqa: E402
from pipeline_lib import _read_bounded_regular_file, load_json_bytes, load_json_file  # noqa: E402


def validate(review: object, references: set[str], today: dt.date) -> None:
    fields = {"schemaVersion", "status", "reviewedAt", "validUntil", "reviewedBy",
              "decision", "actionReferences", "advisories", "auditReportSha256"}
    if not isinstance(review, dict) or set(review) != fields:
        raise ValueError("invalid Action risk review fields")
    if type(review["schemaVersion"]) is not int or review["schemaVersion"] != 1:
        raise ValueError("unsupported Action risk review schema")
    if (not isinstance(review["auditReportSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", review["auditReportSha256"])):
        raise ValueError("invalid reviewed advisory report hash")
    for field in ("reviewedBy", "decision"):
        if not isinstance(review[field], str) or not review[field].strip():
            raise ValueError(f"missing Action risk review {field}")
    actions = review["actionReferences"]
    if (not isinstance(actions, list) or any(not isinstance(item, str) for item in actions)
            or len(actions) != len(set(actions)) or set(actions) != references):
        raise ValueError("Action risk review is not bound to the exact workflow commits")
    advisories = review["advisories"]
    if (not isinstance(advisories, list) or any(
            not isinstance(item, str) or not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", item)
            for item in advisories) or len(advisories) != len(set(advisories))):
        raise ValueError("invalid reviewed advisory list")
    try:
        start = dt.date.fromisoformat(review["reviewedAt"])
        end = dt.date.fromisoformat(review["validUntil"])
    except (TypeError, ValueError) as error:
        raise ValueError("invalid Action review dates") from error
    if (start.isoformat() != review["reviewedAt"] or end.isoformat() != review["validUntil"]
            or not start <= today <= end or not 0 <= (end - start).days <= 14):
        raise ValueError("Action risk review is expired, future-dated, or longer than 14 days")
    if review["status"] != "approved":
        raise ValueError("formal release blocked pending Action dependency risk review")


def validate_report(review: dict, data: bytes, references: set[str]) -> None:
    if hashlib.sha256(data).hexdigest() != review.get("auditReportSha256"):
        raise ValueError("advisory report does not match the reviewed hash")
    report = load_json_bytes(data, "reviewed Action dependency report", maximum=512 * 1024)
    if not isinstance(report, dict) or report.get("schemaVersion") != 1:
        raise ValueError("invalid reviewed advisory report schema")
    actions = report.get("actions")
    if not isinstance(actions, list) or any(not isinstance(item, str) for item in actions):
        raise ValueError("invalid reviewed advisory Action inventory")
    if set(actions) != references or len(actions) != len(references):
        raise ValueError("reviewed advisory report is for different Action commits")
    try:
        scanned = dt.datetime.fromisoformat(report["scannedAt"])
        reviewed = dt.date.fromisoformat(review["reviewedAt"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid reviewed advisory report timestamp") from error
    if scanned.tzinfo is None or scanned.astimezone(dt.timezone.utc).date() != reviewed:
        raise ValueError("advisory inventory must be refreshed on the review date")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("invalid reviewed advisory findings")
    identities: set[str] = set()
    for finding in findings:
        if (not isinstance(finding, dict) or finding.get("action") not in references
                or not isinstance(finding.get("advisories"), list)):
            raise ValueError("invalid reviewed advisory finding")
        for advisory in finding["advisories"]:
            if (not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str)
                    or advisory.get("severity") not in {"low", "medium", "high", "critical"}):
                raise ValueError("invalid reviewed advisory record")
            identities.add(advisory["id"])
    if identities != set(review["advisories"]):
        raise ValueError("Action review must cover every inventoried advisory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--workflows", required=True, type=Path)
    parser.add_argument("--audit-report", required=True, type=Path)
    options = parser.parse_args()
    try:
        references: set[str] = set()
        for workflow in workflow_paths([options.workflows]):
            references.update(audit_workflow(workflow))
        review = load_json_file(options.review, "Action risk review", maximum=64 * 1024)
        validate(review, references, dt.datetime.now(dt.timezone.utc).date())
        validate_report(review, _read_bounded_regular_file(
            options.audit_report, "reviewed Action dependency report", 512 * 1024), references)
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(2, f"Action release review: {error}\n")
    print("current Action risk review matches every immutable workflow reference")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
