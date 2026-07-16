from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

ECOSYSTEMS = ("npm", "PyPI", "Maven", "Go", "RubyGems", "NuGet")
BASE = "https://storage.googleapis.com/osv-vulnerabilities"
SEED = "repair-evidence-contract-locked-seed"
MAIN_PER_ECOSYSTEM = 40
ENRICHED_PER_ECOSYSTEM = 12
MAX_DOWNLOAD = 1_500_000_000
MAX_MEMBER = 20_000_000
MAX_BODY = 8_000_000
ROOT = Path(os.environ.get("OUTPUT_DIR", "frozen_evidence")).resolve()
DOWNLOADS = ROOT / "downloads"
RAW = ROOT / "records"
RECEIPTS = ROOT / "receipts"
USER_AGENT = "repair-evidence-audit/1"
RECEIPT_ROWS: list[dict[str, Any]] = []


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(value: str) -> str:
    return (re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "item")[:180]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def download_dump(ecosystem: str) -> dict[str, Any]:
    url = f"{BASE}/{ecosystem}/all.zip"
    target = DOWNLOADS / f"{ecosystem}_all.zip"
    partial = target.with_suffix(".partial")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/zip"})
    size = 0
    h = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=180) as response, partial.open("wb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_DOWNLOAD:
                raise ValueError(f"archive too large: {ecosystem}")
            h.update(chunk)
            out.write(chunk)
        headers = {k.lower(): v for k, v in response.headers.items() if k.lower() in {"etag", "last-modified", "content-length", "content-type"}}
    partial.replace(target)
    if not zipfile.is_zipfile(target):
        raise ValueError(f"invalid archive: {ecosystem}")
    return {"ecosystem": ecosystem, "url": url, "path": str(target.relative_to(ROOT)), "bytes": size, "sha256": h.hexdigest(), "headers": headers}


def request_bytes(url: str, *, accept: str = "application/json", auth: bool = False, attempts: int = 3) -> tuple[int | None, dict[str, str], bytes, str | None]:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if auth and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    last_error: str | None = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=45) as response:
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise ValueError("response too large")
                response_headers = {k.lower(): v for k, v in response.headers.items() if k.lower() in {"etag", "last-modified", "content-length", "content-type", "x-ratelimit-remaining"}}
                return int(response.status), response_headers, body, None
        except urllib.error.HTTPError as exc:
            body = exc.read(min(MAX_BODY, 256 * 1024))
            response_headers = {k.lower(): v for k, v in exc.headers.items() if k.lower() in {"etag", "last-modified", "content-length", "content-type", "x-ratelimit-remaining"}}
            if exc.code in {403, 429, 500, 502, 503, 504} and attempt + 1 < attempts:
                time.sleep(2 ** attempt)
                continue
            return int(exc.code), response_headers, body, f"HTTP {exc.code}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    return None, {}, b"", last_error or "request failed"


def receipt(kind: str, url: str, *, accept: str = "application/json", auth: bool = False) -> dict[str, Any]:
    status, headers, body, error = request_bytes(url, accept=accept, auth=auth)
    rid = f"r{len(RECEIPT_ROWS):05d}"
    body_path = None
    body_hash = None
    if body:
        body_hash = digest_bytes(body)
        suffix = ".json" if "json" in headers.get("content-type", "").lower() else ".bin"
        target = RECEIPTS / f"{rid}{suffix}"
        target.write_bytes(body)
        body_path = str(target.relative_to(ROOT))
    row = {"receipt_id": rid, "kind": kind, "url": url, "status": status, "resolved": status is not None and 200 <= status < 300, "headers": headers, "body_sha256": body_hash, "body_path": body_path, "error": error}
    RECEIPT_ROWS.append(row)
    return row


def receipt_json(row: dict[str, Any]) -> Any | None:
    if not row.get("body_path"):
        return None
    try:
        return json.loads((ROOT / row["body_path"]).read_text(encoding="utf-8"))
    except Exception:
        return None


def fixed_values(entries: list[dict[str, Any]]) -> list[str]:
    values: set[str] = set()
    for affected in entries:
        for range_obj in affected.get("ranges") or []:
            for event in range_obj.get("events") or []:
                value = event.get("fixed")
                if isinstance(value, str) and value and value != "0":
                    values.add(value)
    return sorted(values)


def candidate_value(entries: list[dict[str, Any]], fixed: list[str]) -> tuple[str | None, str]:
    if len(fixed) == 1:
        return fixed[0], "fixed-boundary"
    for field in ("last_affected", "introduced"):
        values: list[str] = []
        for affected in entries:
            for range_obj in affected.get("ranges") or []:
                for event in range_obj.get("events") or []:
                    value = event.get(field)
                    if isinstance(value, str) and value and value != "0":
                        values.append(value)
        if values:
            return sorted(set(values))[-1 if field == "last_affected" else 0], field
    versions = sorted({str(v) for affected in entries for v in (affected.get("versions") or []) if v})
    return (versions[-1], "explicit-affected") if versions else (None, "unavailable")


def reference_urls(record: dict[str, Any]) -> list[str]:
    return sorted({ref.get("url") for ref in (record.get("references") or []) if isinstance(ref, dict) and isinstance(ref.get("url"), str) and ref["url"].startswith(("https://", "http://"))})


def parse_units(ecosystem: str, archive: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    units: dict[tuple[str, str], dict[str, Any]] = {}
    counts: defaultdict[str, int] = defaultdict(int)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            counts["members"] += 1
            if info.file_size > MAX_MEMBER:
                counts["oversized"] += 1
                continue
            try:
                record = json.loads(zf.read(info))
            except Exception:
                counts["parse_failed"] += 1
                continue
            advisory_id = record.get("id") if isinstance(record, dict) else None
            if not isinstance(advisory_id, str) or advisory_id.startswith("MAL-") or record.get("withdrawn"):
                continue
            grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
            for affected in record.get("affected") or []:
                package = affected.get("package") or {}
                if package.get("ecosystem") == ecosystem and isinstance(package.get("name"), str) and (affected.get("ranges") or affected.get("versions")):
                    grouped[package["name"]].append(affected)
            for package, entries in grouped.items():
                key = (advisory_id, package)
                if key in units:
                    units[key]["affected_entries"].extend(entries)
                    units[key]["fixed_candidates"] = fixed_values(units[key]["affected_entries"])
                    units[key]["candidate_version"], units[key]["candidate_basis"] = candidate_value(units[key]["affected_entries"], units[key]["fixed_candidates"])
                    continue
                fixed = fixed_values(entries)
                candidate, basis = candidate_value(entries, fixed)
                selection = hashlib.sha256(f"{SEED}\0{advisory_id}\0{ecosystem}\0{package}".encode()).hexdigest()
                units[key] = {"advisory_id": advisory_id, "aliases": sorted(set(record.get("aliases") or [])), "ecosystem": ecosystem, "package": package, "published": record.get("published"), "modified": record.get("modified"), "summary": str(record.get("summary") or "")[:800], "affected_entries": entries, "fixed_candidates": fixed, "candidate_version": candidate, "candidate_basis": basis, "references": record.get("references") or [], "normalized_record_sha256": digest_bytes(canonical(record)), "source_archive_member": info.filename, "selection_key": selection, "source_record": record}
                counts["eligible"] += 1
    rows = sorted(units.values(), key=lambda row: (row["selection_key"], row["advisory_id"], row["package"]))
    return rows, dict(counts)


def github_repo(url: str) -> tuple[str, str] | None:
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2 or parts[0] in {"advisories", "security"}:
        return None
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    return parts[0], repo


def commit_ref(url: str) -> tuple[str, str, str] | None:
    repo = github_repo(url)
    parts = [part for part in urllib.parse.urlparse(url).path.split("/") if part]
    if repo and len(parts) >= 4 and parts[2] == "commit" and re.fullmatch(r"[0-9a-fA-F]{7,64}", parts[3].split(".")[0]):
        return repo[0], repo[1], parts[3].split(".")[0]
    return None


def pull_ref(url: str) -> tuple[str, str, int] | None:
    repo = github_repo(url)
    parts = [part for part in urllib.parse.urlparse(url).path.split("/") if part]
    if repo and len(parts) >= 4 and parts[2] == "pull" and parts[3].isdigit():
        return repo[0], repo[1], int(parts[3])
    return None


def api(owner: str, repo: str, path: str) -> str:
    return f"https://api.github.com/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}/{path}"


def repair_candidates(urls: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    repairs: list[dict[str, Any]] = []
    attempts: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for url in urls:
        parsed = commit_ref(url)
        if parsed:
            owner, repo, sha = parsed
            if (owner, repo, sha) in seen:
                continue
            seen.add((owner, repo, sha))
            row = receipt("github-commit", api(owner, repo, f"commits/{urllib.parse.quote(sha, safe='')}"), auth=True)
            attempts.append(row["receipt_id"])
            data = receipt_json(row)
            resolved_sha = data.get("sha") if isinstance(data, dict) else None
            if row["resolved"] and isinstance(resolved_sha, str):
                repairs.append({"owner": owner, "repo": repo, "sha": resolved_sha, "receipt_id": row["receipt_id"], "source_url": url, "kind": "commit"})
            continue
        parsed_pull = pull_ref(url)
        if parsed_pull:
            owner, repo, number = parsed_pull
            row = receipt("github-pull", api(owner, repo, f"pulls/{number}"), auth=True)
            attempts.append(row["receipt_id"])
            data = receipt_json(row)
            merge_sha = data.get("merge_commit_sha") if isinstance(data, dict) else None
            if row["resolved"] and isinstance(merge_sha, str) and merge_sha:
                repairs.append({"owner": owner, "repo": repo, "sha": merge_sha, "receipt_id": row["receipt_id"], "source_url": url, "kind": "pull-merge"})
    return repairs, attempts


def candidate_tags(version: str, package: str) -> list[str]:
    value = version.lstrip("v")
    artifact = package.split(":")[-1].split("/")[-1]
    return list(dict.fromkeys([f"v{value}", value, f"{artifact}-{value}", f"{artifact}_v{value}", f"release-{value}"]))


def resolve_tag(urls: list[str], repos: list[tuple[str, str]], version: str, package: str) -> tuple[dict[str, Any] | None, list[str]]:
    attempts: list[str] = []
    ordered_repos: list[tuple[str, str]] = []
    for url in urls:
        parsed = github_repo(url)
        if parsed and parsed not in ordered_repos:
            ordered_repos.append(parsed)
    for repo in repos:
        if repo not in ordered_repos:
            ordered_repos.insert(0, repo)
    for owner, repo in ordered_repos[:8]:
        for tag in candidate_tags(version, package):
            row = receipt("github-tag-ref", api(owner, repo, f"git/ref/tags/{urllib.parse.quote(tag, safe='')}"), auth=True)
            attempts.append(row["receipt_id"])
            data = receipt_json(row)
            obj = data.get("object") if isinstance(data, dict) else None
            if not (row["resolved"] and isinstance(obj, dict) and isinstance(obj.get("sha"), str)):
                continue
            target_sha = obj["sha"]
            if obj.get("type") == "tag":
                nested = receipt("github-annotated-tag", api(owner, repo, f"git/tags/{urllib.parse.quote(target_sha, safe='')}"), auth=True)
                attempts.append(nested["receipt_id"])
                nested_data = receipt_json(nested)
                nested_obj = nested_data.get("object") if isinstance(nested_data, dict) else None
                if nested["resolved"] and isinstance(nested_obj, dict) and isinstance(nested_obj.get("sha"), str):
                    target_sha = nested_obj["sha"]
            return {"owner": owner, "repo": repo, "tag": tag, "target_sha": target_sha, "receipt_id": row["receipt_id"]}, attempts
    return None, attempts


def prove_containment(repairs: list[dict[str, Any]], tag: dict[str, Any] | None) -> tuple[bool, dict[str, Any] | None, list[str]]:
    attempts: list[str] = []
    if not tag:
        return False, None, attempts
    for repair in repairs:
        if repair["owner"] != tag["owner"] or repair["repo"] != tag["repo"]:
            continue
        row = receipt("github-compare", api(tag["owner"], tag["repo"], f"compare/{urllib.parse.quote(repair['sha'], safe='')}...{urllib.parse.quote(tag['target_sha'], safe='')}"), auth=True)
        attempts.append(row["receipt_id"])
        data = receipt_json(row)
        status = data.get("status") if isinstance(data, dict) else None
        if row["resolved"] and status in {"ahead", "identical"}:
            return True, {"repair_sha": repair["sha"], "release_target_sha": tag["target_sha"], "compare_status": status, "receipt_id": row["receipt_id"]}, attempts
    return False, None, attempts


def go_escape(value: str) -> str:
    return "".join("!" + char.lower() if "A" <= char <= "Z" else char for char in value)


def registry_url(ecosystem: str, package: str, version: str) -> tuple[str | None, str]:
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='')}/{urllib.parse.quote(version, safe='')}", "application/json"
    if ecosystem == "PyPI":
        return f"https://pypi.org/pypi/{urllib.parse.quote(package, safe='')}/{urllib.parse.quote(version, safe='')}/json", "application/json"
    if ecosystem == "Maven" and ":" in package:
        group, artifact = package.split(":", 1)
        group_path = "/".join(urllib.parse.quote(part, safe="") for part in group.split("."))
        artifact_q, version_q = urllib.parse.quote(artifact, safe=""), urllib.parse.quote(version, safe="")
        return f"https://repo1.maven.org/maven2/{group_path}/{artifact_q}/{version_q}/{artifact_q}-{version_q}.pom", "application/xml"
    if ecosystem == "Go":
        version_value = version if version.startswith("v") else "v" + version
        return f"https://proxy.golang.org/{go_escape(package)}/@v/{urllib.parse.quote(version_value, safe='')}.info", "application/json"
    if ecosystem == "RubyGems":
        return f"https://rubygems.org/api/v2/rubygems/{urllib.parse.quote(package, safe='')}/versions/{urllib.parse.quote(version, safe='')}.json", "application/json"
    if ecosystem == "NuGet":
        package_lower, version_lower = package.lower(), version.lower()
        return f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package_lower, safe='')}/{urllib.parse.quote(version_lower, safe='')}/{urllib.parse.quote(package_lower, safe='')}.nuspec", "application/xml"
    return None, ""


def complete_evidence(unit: dict[str, Any]) -> dict[str, Any]:
    version = unit["fixed_candidates"][0]
    urls = reference_urls(unit["source_record"])
    repairs, repair_attempts = repair_candidates(urls)
    repair_repos = list(dict.fromkeys((item["owner"], item["repo"]) for item in repairs))
    tag, tag_attempts = resolve_tag(urls, repair_repos, version, unit["package"])
    contained, containment, compare_attempts = prove_containment(repairs, tag)
    url, accept = registry_url(unit["ecosystem"], unit["package"], version)
    registry = receipt("package-registry", url, accept=accept) if url else None
    return {"advisory_id": unit["advisory_id"], "ecosystem": unit["ecosystem"], "package": unit["package"], "fixed_candidate": version, "selection_key": unit["selection_key"], "normalized_record_sha256": unit["normalized_record_sha256"], "evidence_collection_complete": True, "repair_candidates": repairs, "repair_attempt_receipts": repair_attempts, "release_artifact": tag, "release_attempt_receipts": tag_attempts, "repair_in_release": contained, "containment_evidence": containment, "containment_attempt_receipts": compare_attempts, "registry_url": url, "registry_receipt_id": registry["receipt_id"] if registry else None, "registry_reference_resolved": bool(registry and registry["resolved"]), "package_published": bool(registry and registry["resolved"]), "authorization_ready": bool(contained and registry and registry["resolved"]), "reference_urls": urls}


def main() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    DOWNLOADS.mkdir(parents=True)
    RAW.mkdir(parents=True)
    RECEIPTS.mkdir(parents=True)
    downloads: list[dict[str, Any]] = []
    counters: dict[str, Any] = {}
    main_units: list[dict[str, Any]] = []
    enriched_units: list[dict[str, Any]] = []
    inventory: list[dict[str, Any]] = []
    source_records: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ecosystem in ECOSYSTEMS:
        download = download_dump(ecosystem)
        downloads.append(download)
        rows, counts = parse_units(ecosystem, ROOT / download["path"])
        counters[ecosystem] = counts
        for rank, row in enumerate(rows):
            inventory.append({"ecosystem": ecosystem, "advisory_id": row["advisory_id"], "package": row["package"], "selection_key": row["selection_key"], "normalized_record_sha256": row["normalized_record_sha256"], "fixed_candidate_count": len(row["fixed_candidates"]), "population_rank": rank})
        selected = rows[:MAIN_PER_ECOSYSTEM]
        if len(selected) != MAIN_PER_ECOSYSTEM:
            raise SystemExit(f"main shortfall: {ecosystem}={len(selected)}")
        for rank, row in enumerate(selected):
            record_path = RAW / ecosystem / f"{safe_name(row['advisory_id'])}__{safe_name(row['package'])}.json"
            write_json(record_path, row["source_record"])
            row["source_record_path"] = str(record_path.relative_to(ROOT))
            row["main_rank"] = rank
            source_records[(row["advisory_id"], ecosystem, row["package"])] = row.pop("source_record")
            main_units.append(row)
        enriched = [row for row in selected if len(row["fixed_candidates"]) == 1 and any(re.search(r"/(commit|pull|releases/tag|tags?)/", url, re.I) for url in reference_urls(source_records[(row["advisory_id"], ecosystem, row["package"])]))][:ENRICHED_PER_ECOSYSTEM]
        if len(enriched) != ENRICHED_PER_ECOSYSTEM:
            raise SystemExit(f"enriched shortfall: {ecosystem}={len(enriched)}")
        for rank, row in enumerate(enriched):
            out = dict(row)
            out["enriched_rank"] = rank
            enriched_units.append(out)
    evidence_units = [row for row in main_units if len(row["fixed_candidates"]) == 1]
    ledger: list[dict[str, Any]] = []
    for row in evidence_units:
        work = dict(row)
        work["source_record"] = source_records[(row["advisory_id"], row["ecosystem"], row["package"])]
        ledger.append(complete_evidence(work))
    write_jsonl(ROOT / "main_units.jsonl", main_units)
    write_jsonl(ROOT / "enriched_units.jsonl", enriched_units)
    write_jsonl(ROOT / "evidence_ledger.jsonl", ledger)
    write_jsonl(ROOT / "eligible_inventory.jsonl", inventory)
    write_jsonl(ROOT / "receipt_manifest.jsonl", RECEIPT_ROWS)
    write_json(ROOT / "download_manifest.json", downloads)
    write_json(ROOT / "parse_counters.json", counters)
    write_json(ROOT / "experiment_lock.json", {"seed": SEED, "ecosystems": list(ECOSYSTEMS), "main_units_per_ecosystem": MAIN_PER_ECOSYSTEM, "enriched_units_per_ecosystem": ENRICHED_PER_ECOSYSTEM, "selection": "ascending SHA-256(seed, advisory id, ecosystem, package)", "evidence_denominator": "all main-corpus units with exactly one fixed candidate; every unit receives the same evidence-attempt procedure", "replacement_policy": "none", "failure_policy": "retain unresolved requests and failed records"})
    summary = {"generated_at_utc": now(), "main_units": len(main_units), "enriched_units": len(enriched_units), "evidence_units": len(evidence_units), "authorization_ready": sum(1 for row in ledger if row["authorization_ready"]), "repair_containment_proven": sum(1 for row in ledger if row["repair_in_release"]), "registry_publication_proven": sum(1 for row in ledger if row["package_published"]), "receipts": len(RECEIPT_ROWS), "per_ecosystem_main": {e: sum(1 for row in main_units if row["ecosystem"] == e) for e in ECOSYSTEMS}, "per_ecosystem_enriched": {e: sum(1 for row in enriched_units if row["ecosystem"] == e) for e in ECOSYSTEMS}}
    write_json(ROOT / "run_summary.json", summary)
    with (ROOT / "source_manifest.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ecosystem", "url", "bytes", "sha256", "etag", "last_modified"])
        writer.writeheader()
        for row in downloads:
            writer.writerow({"ecosystem": row["ecosystem"], "url": row["url"], "bytes": row["bytes"], "sha256": row["sha256"], "etag": row["headers"].get("etag", ""), "last_modified": row["headers"].get("last-modified", "")})
    shutil.rmtree(DOWNLOADS)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
