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
from pipeline_lib import (  # noqa: E402
    _read_bounded_regular_file, load_json_bytes, load_json_file, load_sources, release_tag,
)


def validate(review: object, references: set[str], today: dt.date) -> None:
    fields = {"schemaVersion", "status", "reviewedAt", "validUntil", "reviewedBy",
              "decision", "actionReferences", "advisories", "auditReportSha256",
              "releaseTag", "sourceLockSha256", "workflowSha256", "assessmentSha256"}
    if not isinstance(review, dict) or set(review) != fields:
        raise ValueError("invalid Action risk review fields")
    if type(review["schemaVersion"]) is not int or review["schemaVersion"] != 2:
        raise ValueError("unsupported Action risk review schema")
    for field in ("auditReportSha256", "sourceLockSha256", "assessmentSha256"):
        if (not isinstance(review[field], str)
                or not re.fullmatch(r"[0-9a-f]{64}", review[field])):
            raise ValueError(f"invalid reviewed {field} hash")
    if (not isinstance(review["releaseTag"], str)
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-motrix\.[0-9]+", review["releaseTag"])):
        raise ValueError("invalid approved release tag")
    workflows = review["workflowSha256"]
    if (not isinstance(workflows, dict) or not workflows or any(
            not isinstance(name, str) or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", name)
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for name, digest in workflows.items())):
        raise ValueError("invalid approved workflow scope")
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
    if review["reviewedBy"] == "pending-maintainer-review":
        raise ValueError("approved review requires an explicit maintainer identity")


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


def validate_scope(review: dict, workflows: Path, sources: Path,
                   requested_tag: str, assessment: Path) -> None:
    source_data = _read_bounded_regular_file(sources, "approved source lock", 64 * 1024)
    if (requested_tag != review["releaseTag"]
            or release_tag(load_sources(sources)) != requested_tag):
        raise ValueError("Action risk approval is for a different release tag")
    if hashlib.sha256(source_data).hexdigest() != review["sourceLockSha256"]:
        raise ValueError("source lock differs from the approved release scope")
    digests = {
        f".github/workflows/{path.name}": hashlib.sha256(_read_bounded_regular_file(
            path, "approved workflow", 512 * 1024)).hexdigest()
        for path in workflow_paths([workflows])
    }
    if digests != review["workflowSha256"]:
        raise ValueError("workflow inputs differ from the approved release scope")
    evidence_data = _read_bounded_regular_file(assessment, "call-path assessment", 256 * 1024)
    if hashlib.sha256(evidence_data).hexdigest() != review["assessmentSha256"]:
        raise ValueError("call-path assessment differs from the approved hash")
    evidence = load_json_bytes(evidence_data, "call-path assessment", maximum=256 * 1024)
    if (not isinstance(evidence, dict) or type(evidence.get("schemaVersion")) is not int
            or evidence["schemaVersion"] != 1):
        raise ValueError("invalid approved call-path assessment")
    for field in ("releaseTag", "sourceLockSha256", "workflowSha256",
                  "actionReferences", "auditReportSha256", "reviewedAt"):
        if evidence.get(field) != review[field]:
            raise ValueError(f"call-path assessment has a different {field}")
    records = evidence.get("advisories")
    if (not isinstance(records, list) or any(not isinstance(item, dict) for item in records)
            or sorted(item.get("id", "") for item in records) != sorted(review["advisories"])):
        raise ValueError("call-path assessment must cover every approved advisory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--workflows", required=True, type=Path)
    parser.add_argument("--audit-report", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--assessment", required=True, type=Path)
    options = parser.parse_args()
    try:
        references: set[str] = set()
        for workflow in workflow_paths([options.workflows]):
            references.update(audit_workflow(workflow))
        review = load_json_file(options.review, "Action risk review", maximum=64 * 1024)
        validate(review, references, dt.datetime.now(dt.timezone.utc).date())
        validate_report(review, _read_bounded_regular_file(
            options.audit_report, "reviewed Action dependency report", 512 * 1024), references)
        validate_scope(review, options.workflows, options.sources, options.release_tag, options.assessment)
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(2, f"Action release review: {error}\n")
    print("current Action risk review matches the exact release tag, inputs, evidence, and Actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
