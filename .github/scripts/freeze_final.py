from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Any

scope_path = Path(__file__).with_name("freeze_scoped.py")
source = scope_path.read_text(encoding="utf-8")
if not source.rstrip().endswith("module.main()"):
    raise SystemExit("scope wrapper shape changed")
source = source.rsplit("module.main()", 1)[0]
namespace: dict[str, Any] = {"__file__": str(scope_path), "__name__": "freeze_scope_definitions"}
exec(compile(source, str(scope_path), "exec"), namespace)
module = namespace["module"]
base_complete = namespace["_original_complete"]
tag_score = namespace["_tag_score"]
ref_tag = namespace["_ref_tag"]
deref_tag = namespace["_deref_tag"]


def resolve_tag(urls: list[str], repos: list[tuple[str, str]], version: str, package: str):
    attempts: list[str] = []
    repair_repos = list(dict.fromkeys(repos))[:4]
    if not repair_repos:
        return None, attempts
    direct = []
    for url in urls:
        parsed = ref_tag(url)
        if parsed and (parsed[0], parsed[1]) in repair_repos:
            score = tag_score(parsed[2], version, package)
            if score < 99:
                direct.append((score, *parsed))
    for _, owner, repo, tag in sorted(direct):
        row = module.receipt("github-tag-ref", module.api(owner, repo, f"git/ref/tags/{urllib.parse.quote(tag, safe='')}"), auth=True)
        attempts.append(row["receipt_id"])
        result = deref_tag(owner, repo, tag, row, attempts)
        if result:
            result["source"] = "direct-advisory-reference"
            return result, attempts
    for owner, repo in repair_repos:
        row = module.receipt("github-tags", module.api(owner, repo, "tags?per_page=100"), auth=True)
        attempts.append(row["receipt_id"])
        data = module.receipt_json(row)
        matches = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                tag = item.get("name")
                target = (item.get("commit") or {}).get("sha")
                if isinstance(tag, str) and isinstance(target, str):
                    score = tag_score(tag, version, package)
                    if score < 99:
                        matches.append((score, tag, target))
        if matches:
            score, tag, target = sorted(matches, key=lambda item: (item[0], item[1]))[0]
            return {"owner": owner, "repo": repo, "tag": tag, "target_sha": target, "receipt_id": row["receipt_id"], "source": "tag-inventory", "match_score": score}, attempts
    return None, attempts


def supplemental_registry(ecosystem: str, package: str, version: str):
    attempts = []
    value = version.lower()
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@')}/{urllib.parse.quote(version, safe='')}"
        row = module.receipt("package-registry-publication", url)
        attempts.append(row)
        return row["resolved"], attempts
    if ecosystem == "PyPI":
        url = f"https://pypi.org/pypi/{urllib.parse.quote(package, safe='')}/{urllib.parse.quote(version, safe='')}/json"
        row = module.receipt("package-registry-publication", url)
        attempts.append(row)
        return row["resolved"], attempts
    if ecosystem == "Maven" and ":" in package:
        group, artifact = package.split(":", 1)
        group_path = "/".join(urllib.parse.quote(part, safe="") for part in group.split("."))
        artifact_q, version_q = urllib.parse.quote(artifact, safe=""), urllib.parse.quote(version, safe="")
        repositories = ["https://repo1.maven.org/maven2"]
        if group.startswith("org.jenkins-ci"):
            repositories.extend(("https://repo.jenkins-ci.org/public", "https://repo.jenkins-ci.org/releases"))
        repositories.append("https://plugins.gradle.org/m2")
        for base in repositories:
            url = f"{base}/{group_path}/{artifact_q}/{version_q}/{artifact_q}-{version_q}.pom"
            row = module.receipt("package-registry-publication", url, accept="application/xml")
            attempts.append(row)
            if row["resolved"]:
                return True, attempts
        return False, attempts
    if ecosystem == "Go":
        module_path = module.go_escape(package)
        requested = version if version.startswith("v") else "v" + version
        exact = f"https://proxy.golang.org/{module_path}/@v/{urllib.parse.quote(requested, safe='')}.info"
        row = module.receipt("package-registry-publication", exact)
        attempts.append(row)
        return row["resolved"], attempts
    if ecosystem == "RubyGems":
        exact = f"https://rubygems.org/api/v2/rubygems/{urllib.parse.quote(package, safe='')}/versions/{urllib.parse.quote(version, safe='')}.json"
        row = module.receipt("package-registry-publication", exact)
        attempts.append(row)
        return row["resolved"], attempts
    if ecosystem == "NuGet":
        package_lower = package.lower()
        exact = f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package_lower, safe='')}/{urllib.parse.quote(value, safe='')}/{urllib.parse.quote(package_lower, safe='')}.nuspec"
        row = module.receipt("package-registry-publication", exact, accept="application/xml")
        attempts.append(row)
        return row["resolved"], attempts
    return False, attempts


def complete_evidence(unit: dict[str, Any]):
    result = base_complete(unit)
    attempts = [result["registry_receipt_id"]] if result.get("registry_receipt_id") else []
    if not result.get("package_published"):
        published, supplemental = supplemental_registry(unit["ecosystem"], unit["package"], result["fixed_candidate"])
        attempts.extend(row["receipt_id"] for row in supplemental)
        if published:
            successful = next(row for row in supplemental if row["resolved"])
            result["registry_url"] = successful["url"]
            result["registry_receipt_id"] = successful["receipt_id"]
            result["registry_reference_resolved"] = True
            result["package_published"] = True
    result["registry_attempt_receipts"] = list(dict.fromkeys(attempts))
    result["authorization_ready"] = bool(result.get("repair_in_release") and result.get("package_published"))
    return result


module.parse_units = namespace["parse_units"]
module.resolve_tag = resolve_tag
module.complete_evidence = complete_evidence
module.main()
