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
        if row["resolved"]:
            return True, attempts
        listing = f"https://proxy.golang.org/{module_path}/@v/list"
        row = module.receipt("package-registry-index", listing, accept="text/plain")
        attempts.append(row)
        body = (module.ROOT / row["body_path"]).read_bytes() if row.get("body_path") else b""
        return bool(row["resolved"] and requested in {line.strip() for line in body.decode("utf-8", "replace").splitlines()}), attempts
    if ecosystem == "RubyGems":
        exact = f"https://rubygems.org/api/v2/rubygems/{urllib.parse.quote(package, safe='')}/versions/{urllib.parse.quote(version, safe='')}.json"
        row = module.receipt("package-registry-publication", exact)
        attempts.append(row)
        if row["resolved"]:
            return True, attempts
        listing = f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(package, safe='')}.json"
        row = module.receipt("package-registry-index", listing)
        attempts.append(row)
        data = module.receipt_json(row)
        numbers = {str(item.get("number")).lower() for item in data if isinstance(item, dict)} if isinstance(data, list) else set()
        normalized = value.replace("-", ".")
        return bool(row["resolved"] and any(item == value or item.replace("-", ".") == normalized for item in numbers)), attempts
    if ecosystem == "NuGet":
        package_lower = package.lower()
        exact = f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package_lower, safe='')}/{urllib.parse.quote(value, safe='')}/{urllib.parse.quote(package_lower, safe='')}.nuspec"
        row = module.receipt("package-registry-publication", exact, accept="application/xml")
        attempts.append(row)
        if row["resolved"]:
            return True, attempts
        listing = f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package_lower, safe='')}/index.json"
        row = module.receipt("package-registry-index", listing)
        attempts.append(row)
        data = module.receipt_json(row)
        versions = {str(item).lower() for item in (data.get("versions") or [])} if isinstance(data, dict) else set()
        return bool(row["resolved"] and value in versions), attempts
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
module.resolve_tag = namespace["resolve_tag"]
module.complete_evidence = complete_evidence
module.main()
