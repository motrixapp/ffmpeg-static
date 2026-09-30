#!/usr/bin/env python3
"""Conservatively audit pinned Actions' runtime npm lock entries, not just tags.

This is a lock inventory, not proof that a vulnerable function is reachable in
the bundled Action. Development-only packages are excluded. GitHub API errors
fail closed; no advisory response is interpreted as an empty successful scan.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_workflow_actions import audit_workflow, workflow_paths  # noqa: E402
from pipeline_lib import load_json_bytes  # noqa: E402


def runtime_packages(lock: object) -> set[tuple[str, str]]:
    if not isinstance(lock, dict) or lock.get("lockfileVersion") not in (2, 3):
        raise ValueError("unsupported npm lockfile schema")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or len(packages) > 20_000:
        raise ValueError("missing or oversized npm package inventory")
    result: set[tuple[str, str]] = set()
    for location, package in packages.items():
        if location == "":
            continue
        if (not isinstance(location, str) or not isinstance(package, dict)
                or not location.startswith("node_modules/")):
            raise ValueError("malformed npm package entry")
        if package.get("dev") is True:
            continue
        name = location.rsplit("node_modules/", 1)[-1]
        version = package.get("version")
        if (not re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", name)
                or not isinstance(version, str)
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version)
                or package.get("link") is True):
            raise ValueError(f"unqueryable runtime npm package: {location}")
        result.add((name, version))
    if not result or len(result) > 1000:
        raise ValueError("runtime npm inventory is empty or too large")
    return result


def gh_json(arguments: list[str]) -> object:
    result = subprocess.run(["gh", "api", *arguments], check=True,
                            stdout=subprocess.PIPE, timeout=120)
    return load_json_bytes(result.stdout, "GitHub dependency audit response", maximum=8 * 1024 * 1024)


def action_packages(reference: str) -> set[tuple[str, str]]:
    repository, commit = reference.rsplit("@", 1)
    response = gh_json([f"repos/{repository}/contents/package-lock.json?ref={commit}"])
    if (not isinstance(response, dict) or response.get("type") != "file"
            or response.get("encoding") != "base64" or not isinstance(response.get("content"), str)):
        raise ValueError(f"missing pinned lockfile: {reference}")
    data = base64.b64decode("".join(response["content"].split()), validate=True)
    return runtime_packages(load_json_bytes(data, "pinned Action lockfile", maximum=4 * 1024 * 1024))


def package_advisories(name: str, version: str) -> list[dict[str, str]]:
    pages = gh_json(["--method", "GET", "/advisories", "-f", "ecosystem=npm",
                     "-f", f"affects={name}@{version}", "-F", "per_page=100",
                     "--paginate", "--slurp"])
    if not isinstance(pages, list) or not pages:
        raise ValueError("invalid advisory response")
    result = []
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("invalid advisory page")
        for entry in page:
            if not isinstance(entry, dict):
                raise ValueError("invalid advisory record")
            if "withdrawn_at" not in entry:
                raise ValueError("advisory withdrawal state is missing")
            if entry.get("withdrawn_at") is not None:
                continue
            identity, severity = entry.get("ghsa_id"), entry.get("severity")
            if (not isinstance(identity, str) or not re.fullmatch(
                    r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", identity)
                    or severity not in {"low", "medium", "high", "critical"}):
                raise ValueError("invalid advisory identity or severity")
            result.append({"id": identity, "severity": severity,
                           "url": f"https://github.com/advisories/{identity}"})
    return sorted(result, key=lambda item: item["id"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflows", type=Path)
    options = parser.parse_args()
    try:
        references: set[str] = set()
        for workflow in workflow_paths([options.workflows]):
            references.update(audit_workflow(workflow))
        inventories = {reference: action_packages(reference) for reference in sorted(references)}
        all_packages = set().union(*inventories.values())
        advisories = {}
        for name, version in sorted(all_packages):
            advisories[(name, version)] = package_advisories(name, version)
        findings = [
            {"action": reference, "package": name, "version": version, "advisories": advisories[(name, version)]}
            for reference, packages in inventories.items()
            for name, version in sorted(packages) if advisories[(name, version)]
        ]
        high = any(advisory["severity"] in {"high", "critical"}
                   for finding in findings for advisory in finding["advisories"])
        print(json.dumps({"schemaVersion": 1, "scannedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                          "actions": sorted(references), "runtimePackageVersions": len(all_packages),
                          "findings": findings, "unreviewedHighOrCritical": high}, indent=2))
        return 1 if high else 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"Action dependency audit failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
