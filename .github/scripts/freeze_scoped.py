from __future__ import annotations

import importlib.util
import re
import urllib.parse
from pathlib import Path
from typing import Any

TARGET = Path(__file__).with_name("freeze_osv.py")
spec = importlib.util.spec_from_file_location("freeze_osv", TARGET)
if spec is None or spec.loader is None:
    raise SystemExit("acquisition module unavailable")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

_PATTERNS = tuple(
    re.compile(value, re.IGNORECASE)
    for value in (
        r"\bai\b",
        r"\bml\b",
        r"\bllm\b",
        r"artificial[- ]intelligence",
        r"machine[- ]learning",
        r"large[- ]language[- ]model",
        r"prompt[- ]injection",
        r"generative[- ]model",
        r"chatgpt",
        r"openai",
        r"anthropic",
        r"copilot",
        r"claude",
        r"tensorflow",
        r"pytorch",
        r"transformer",
        r"neural[- ]network",
        r"agentic",
    )
)
_original_parse = module.parse_units
_original_complete = module.complete_evidence


def parse_units(ecosystem: str, archive: Path):
    rows, counts = _original_parse(ecosystem, archive)
    kept = []
    excluded = 0
    for row in rows:
        record = row.get("source_record") or {}
        text = "\n".join(
            (
                str(row.get("package") or ""),
                str(row.get("summary") or ""),
                str(record.get("details") or ""),
            )
        )
        if any(pattern.search(text) for pattern in _PATTERNS):
            excluded += 1
        else:
            kept.append(row)
    counts = dict(counts)
    counts["scope_excluded_before_sampling"] = excluded
    return kept, counts


def _ref_tag(url: str):
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) >= 5 and parts[2] == "releases" and parts[3] == "tag":
        return parts[0], parts[1], urllib.parse.unquote("/".join(parts[4:]))
    if len(parts) >= 4 and parts[2] in {"tree", "releases"}:
        return parts[0], parts[1], urllib.parse.unquote("/".join(parts[3:]))
    return None


def _tag_score(tag: str, version: str, package: str) -> int:
    value = version.lower().lstrip("v")
    raw = urllib.parse.unquote(tag).lower().removeprefix("refs/tags/")
    stripped = raw[1:] if raw.startswith("v") else raw
    if stripped == value:
        return 0
    leaf = package.split(":")[-1].split("/")[-1].lower()
    exact = {
        f"{leaf}-{value}",
        f"{leaf}-v{value}",
        f"{leaf}_v{value}",
        f"{leaf}/{value}",
        f"{leaf}/v{value}",
        f"release-{value}",
        f"release/{value}",
        f"release/v{value}",
    }
    if raw in exact:
        return 1
    suffixes = (f"/v{value}", f"/{value}", f"-v{value}", f"-{value}", f"_v{value}")
    if any(raw.endswith(suffix) for suffix in suffixes):
        return 2
    return 99


def _deref_tag(owner: str, repo: str, tag: str, first_receipt: dict[str, Any], attempts: list[str]):
    data = module.receipt_json(first_receipt)
    obj = data.get("object") if isinstance(data, dict) else None
    if not (first_receipt["resolved"] and isinstance(obj, dict) and isinstance(obj.get("sha"), str)):
        return None
    target = obj["sha"]
    if obj.get("type") == "tag":
        nested = module.receipt("github-annotated-tag", module.api(owner, repo, f"git/tags/{urllib.parse.quote(target, safe='')}"), auth=True)
        attempts.append(nested["receipt_id"])
        nested_data = module.receipt_json(nested)
        nested_obj = nested_data.get("object") if isinstance(nested_data, dict) else None
        if nested["resolved"] and isinstance(nested_obj, dict) and isinstance(nested_obj.get("sha"), str):
            target = nested_obj["sha"]
    return {"owner": owner, "repo": repo, "tag": tag, "target_sha": target, "receipt_id": first_receipt["receipt_id"]}


def resolve_tag(urls: list[str], repos: list[tuple[str, str]], version: str, package: str):
    attempts: list[str] = []
    ordered: list[tuple[str, str]] = []
    direct: list[tuple[int, str, str, str]] = []
    for url in urls:
        parsed_repo = module.github_repo(url)
        if parsed_repo and parsed_repo not in ordered:
            ordered.append(parsed_repo)
        parsed_tag = _ref_tag(url)
        if parsed_tag:
            score = _tag_score(parsed_tag[2], version, package)
            if score < 99:
                direct.append((score, *parsed_tag))
    for repo in reversed(repos):
        if repo in ordered:
            ordered.remove(repo)
        ordered.insert(0, repo)
    candidates = list(module.candidate_tags(version, package))
    candidates.extend((f"release/v{version.lstrip('v')}", f"release/{version.lstrip('v')}"))
    for _, owner, repo, tag in sorted(direct):
        row = module.receipt("github-tag-ref", module.api(owner, repo, f"git/ref/tags/{urllib.parse.quote(tag, safe='')}"), auth=True)
        attempts.append(row["receipt_id"])
        result = _deref_tag(owner, repo, tag, row, attempts)
        if result:
            result["source"] = "direct-advisory-reference"
            return result, attempts
    for owner, repo in ordered[:8]:
        for tag in dict.fromkeys(candidates):
            row = module.receipt("github-tag-ref", module.api(owner, repo, f"git/ref/tags/{urllib.parse.quote(tag, safe='')}"), auth=True)
            attempts.append(row["receipt_id"])
            result = _deref_tag(owner, repo, tag, row, attempts)
            if result:
                result["source"] = "generated-candidate"
                return result, attempts
        matches = []
        for fragment in (version.lstrip("v"), f"v{version.lstrip('v')}"):
            row = module.receipt("github-matching-tags", module.api(owner, repo, f"git/matching-refs/tags/{urllib.parse.quote(fragment, safe='')}"), auth=True)
            attempts.append(row["receipt_id"])
            data = module.receipt_json(row)
            if isinstance(data, list):
                for item in data:
                    ref = item.get("ref") if isinstance(item, dict) else None
                    obj = item.get("object") if isinstance(item, dict) else None
                    if isinstance(ref, str) and isinstance(obj, dict) and isinstance(obj.get("sha"), str):
                        tag = ref.removeprefix("refs/tags/")
                        score = _tag_score(tag, version, package)
                        if score < 99:
                            matches.append((score, tag, obj.get("type"), obj["sha"], row))
        if matches:
            _, tag, object_type, target, row = sorted(matches, key=lambda item: (item[0], item[1]))[0]
            synthetic = dict(row)
            synthetic["resolved"] = True
            synthetic["body_path"] = None
            result = {"owner": owner, "repo": repo, "tag": tag, "target_sha": target, "receipt_id": row["receipt_id"], "source": "matching-ref"}
            if object_type == "tag":
                nested = module.receipt("github-annotated-tag", module.api(owner, repo, f"git/tags/{urllib.parse.quote(target, safe='')}"), auth=True)
                attempts.append(nested["receipt_id"])
                nested_data = module.receipt_json(nested)
                nested_obj = nested_data.get("object") if isinstance(nested_data, dict) else None
                if nested["resolved"] and isinstance(nested_obj, dict) and isinstance(nested_obj.get("sha"), str):
                    result["target_sha"] = nested_obj["sha"]
            return result, attempts
    return None, attempts


def _registry_attempts(ecosystem: str, package: str, version: str):
    attempts: list[dict[str, Any]] = []
    value = version.lower()
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@')}"
        row = module.receipt("package-registry-index", url)
        attempts.append(row)
        data = module.receipt_json(row)
        return bool(row["resolved"] and isinstance(data, dict) and version in (data.get("versions") or {})), attempts
    if ecosystem == "PyPI":
        url = f"https://pypi.org/pypi/{urllib.parse.quote(package, safe='')}/json"
        row = module.receipt("package-registry-index", url)
        attempts.append(row)
        data = module.receipt_json(row)
        releases = data.get("releases") if isinstance(data, dict) else None
        return bool(row["resolved"] and isinstance(releases, dict) and version in releases), attempts
    if ecosystem == "Maven" and ":" in package:
        group, artifact = package.split(":", 1)
        group_path = "/".join(urllib.parse.quote(part, safe="") for part in group.split("."))
        artifact_q = urllib.parse.quote(artifact, safe="")
        version_q = urllib.parse.quote(version, safe="")
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
        url = f"https://proxy.golang.org/{module_path}/@v/list"
        row = module.receipt("package-registry-index", url, accept="text/plain")
        attempts.append(row)
        body = b""
        if row.get("body_path"):
            body = (module.ROOT / row["body_path"]).read_bytes()
        versions = {line.strip() for line in body.decode("utf-8", "replace").splitlines() if line.strip()}
        return bool(row["resolved"] and requested in versions), attempts
    if ecosystem == "RubyGems":
        url = f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(package, safe='')}.json"
        row = module.receipt("package-registry-index", url)
        attempts.append(row)
        data = module.receipt_json(row)
        values = {str(item.get("number")) for item in data if isinstance(item, dict)} if isinstance(data, list) else set()
        normalized = value.replace("-", ".")
        return bool(row["resolved"] and any(item.lower() == value or item.lower().replace("-", ".") == normalized for item in values)), attempts
    if ecosystem == "NuGet":
        package_lower = package.lower()
        url = f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package_lower, safe='')}/index.json"
        row = module.receipt("package-registry-index", url)
        attempts.append(row)
        data = module.receipt_json(row)
        values = {str(item).lower() for item in (data.get("versions") or [])} if isinstance(data, dict) else set()
        return bool(row["resolved"] and value in values), attempts
    return False, attempts


def complete_evidence(unit: dict[str, Any]):
    result = _original_complete(unit)
    published, attempts = _registry_attempts(unit["ecosystem"], unit["package"], result["fixed_candidate"])
    result["registry_attempt_receipts"] = [row["receipt_id"] for row in attempts]
    if published:
        successful = next(row for row in attempts if row["resolved"])
        result["registry_url"] = successful["url"]
        result["registry_receipt_id"] = successful["receipt_id"]
        result["registry_reference_resolved"] = True
        result["package_published"] = True
    else:
        result["registry_reference_resolved"] = False
        result["package_published"] = False
    result["authorization_ready"] = bool(result["repair_in_release"] and result["package_published"])
    return result


module.parse_units = parse_units
module.resolve_tag = resolve_tag
module.complete_evidence = complete_evidence
module.main()
