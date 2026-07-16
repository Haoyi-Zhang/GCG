from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

ROOT = Path("frozen_evidence")


def rows(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def candidate(unit):
    explicit = [str(value) for affected in unit.get("affected_entries") or [] for value in (affected.get("versions") or []) if value]
    if explicit:
        return explicit[-1], "explicit-affected"
    last = [str(event["last_affected"]) for affected in unit.get("affected_entries") or [] for rng in (affected.get("ranges") or []) for event in (rng.get("events") or []) if event.get("last_affected")]
    if last:
        return last[-1], "last-affected"
    introduced = [str(event["introduced"]) for affected in unit.get("affected_entries") or [] for rng in (affected.get("ranges") or []) for event in (rng.get("events") or []) if event.get("introduced") and str(event.get("introduced")) != "0"]
    return (introduced[0], "introduced-boundary") if introduced else (None, "unavailable")


def purl(ecosystem, package, version):
    version_q = urllib.parse.quote(version, safe=".-_~+")
    if ecosystem == "Maven" and ":" in package:
        group, artifact = package.split(":", 1)
        return f"pkg:maven/{urllib.parse.quote(group, safe='.-_~')}/{urllib.parse.quote(artifact, safe='.-_~')}@{version_q}"
    kind = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "RubyGems": "gem", "NuGet": "nuget"}.get(ecosystem)
    if not kind:
        return None
    package_q = "/".join(urllib.parse.quote(part, safe=".-_~") for part in package.split("/"))
    return f"pkg:{kind}/{package_q}@{version_q}"


components = []
manifest = []
for unit in rows(ROOT / "main_units.jsonl"):
    version, basis = candidate(unit)
    package_url = purl(unit["ecosystem"], unit["package"], version) if version else None
    if not package_url:
        continue
    key = f"{unit['advisory_id']}|{unit['ecosystem']}|{unit['package']}"
    components.append({"type": "library", "bom-ref": key, "name": unit["package"], "version": version, "purl": package_url, "properties": [{"name": "repair-evidence:unit-key", "value": key}, {"name": "repair-evidence:candidate-basis", "value": basis}]})
    manifest.append({"unit_key": key, "advisory_id": unit["advisory_id"], "aliases": unit.get("aliases") or [], "ecosystem": unit["ecosystem"], "package": unit["package"], "version": version, "candidate_basis": basis, "purl": package_url})

bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "application", "name": "repair-evidence-candidate-set", "version": "frozen"}}, "components": components}
(ROOT / "candidate.cdx.json").write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with (ROOT / "candidate_manifest.jsonl").open("w", encoding="utf-8") as handle:
    for item in manifest:
        handle.write(json.dumps(item, sort_keys=True) + "\n")
print(json.dumps({"components": len(components)}, indent=2))
