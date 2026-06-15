"""Software Bill of Materials (SBOM) export.

Enumerates every declared dependency (reusing the manifest parsers from the
dependency scanner) and emits an SBOM in either CycloneDX 1.5 or SPDX 2.3 JSON.
This is metadata-only — no network calls — so it is fast and safe to run on any
checkout. License/vulnerability enrichment is intentionally left to the dedicated
scan phases; the SBOM records what is present.
"""
import datetime as _dt
import hashlib
import json
import uuid
from pathlib import Path
from typing import Optional

from .deps_scanner import _MANIFEST_PARSERS, _SKIP_PARTS

# Map our internal ecosystem label -> Package URL (purl) type.
_PURL_TYPE = {
    "PyPI": "pypi", "npm": "npm", "Go": "golang", "RubyGems": "gem",
    "Packagist": "composer", "crates.io": "cargo",
}


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _purl(ecosystem: str, name: str, version: str) -> str:
    ptype = _PURL_TYPE.get(ecosystem, ecosystem.lower())
    return f"pkg:{ptype}/{name}@{version}"


def collect_components(root: Path) -> list[dict]:
    """Return a de-duplicated list of {name, version, ecosystem, file} dicts."""
    seen: set[tuple[str, str, str]] = set()
    out: list[dict] = []
    for filename, (ecosystem, parser) in _MANIFEST_PARSERS.items():
        for dep_file in root.rglob(filename):
            if any(p in _SKIP_PARTS for p in dep_file.parts):
                continue
            rel = str(dep_file.relative_to(root))
            for name, version in parser(dep_file):
                key = (ecosystem, name, version)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"name": name, "version": version,
                            "ecosystem": ecosystem, "file": rel})
    return sorted(out, key=lambda c: (c["ecosystem"], c["name"].lower(), c["version"]))


def build_cyclonedx(root: Path, project_name: Optional[str] = None) -> dict:
    components = collect_components(root)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{"vendor": "VaultCheck", "name": "vaultcheck"}],
            "component": {
                "type": "application",
                "name": project_name or root.name,
                "bom-ref": project_name or root.name,
            },
        },
        "components": [
            {
                "type": "library",
                "name": c["name"],
                "version": c["version"],
                "purl": _purl(c["ecosystem"], c["name"], c["version"]),
                "bom-ref": _purl(c["ecosystem"], c["name"], c["version"]),
                "properties": [{"name": "vaultcheck:manifest", "value": c["file"]}],
            }
            for c in components
        ],
    }


def build_spdx(root: Path, project_name: Optional[str] = None) -> dict:
    components = collect_components(root)
    name = project_name or root.name
    doc_ns = f"https://vaultcheck/spdx/{name}-{uuid.uuid4()}"
    packages = []
    relationships = []
    root_spdxid = "SPDXRef-RootPackage"
    for i, c in enumerate(components):
        spdxid = f"SPDXRef-Package-{i}"
        packages.append({
            "name": c["name"],
            "SPDXID": spdxid,
            "versionInfo": c["version"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl(c["ecosystem"], c["name"], c["version"]),
            }],
        })
        relationships.append({
            "spdxElementId": root_spdxid,
            "relatedSpdxElement": spdxid,
            "relationshipType": "DEPENDS_ON",
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": doc_ns,
        "creationInfo": {
            "created": _now_iso(),
            "creators": ["Tool: vaultcheck"],
        },
        "packages": [{
            "name": name,
            "SPDXID": root_spdxid,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }] + packages,
        "relationships": relationships,
    }


def generate_sbom(root: Path, fmt: str = "cyclonedx",
                  project_name: Optional[str] = None) -> dict:
    fmt = fmt.lower()
    if fmt in ("cyclonedx", "cdx"):
        return build_cyclonedx(root, project_name)
    if fmt == "spdx":
        return build_spdx(root, project_name)
    raise ValueError(f"Unknown SBOM format: {fmt!r} (use 'cyclonedx' or 'spdx')")
