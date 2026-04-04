#!/usr/bin/env python3
"""
compare-sboms.py — Compare transparenz-generated SBOMs against official published SBOMs.

For each project it produces a detailed diff across:
  - Component count (generated vs official)
  - Package name coverage  (packages in official missing from generated, and vice-versa)
  - PURL accuracy          (PURLs present/absent, ecosystem match)
  - License coverage       (packages with/without license data)
  - Hash coverage          (packages with/without hash data)
  - BSI-relevant gaps      (SHA-512, supplier)

Supports:
  - CycloneDX 1.x JSON
  - SPDX 2.x JSON
  - SPDX 2.x tag-value (.spdx)

Usage:
    python3 scripts/compare-sboms.py [--output-dir DIR] [--json]

Output:
    Prints a human-readable report to stdout.
    Writes per-project JSON detail to --output-dir (default: test-results/sbom-100/comparison).
    With --json: prints machine-readable JSON summary to stdout instead.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Component:
    name: str
    version: str = ""
    purl: str = ""
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)   # alg → value
    supplier: str = ""

    @property
    def identity(self) -> str:
        """Canonical identity for matching: name@version (lowercased)."""
        n = self.name.lower().strip()
        v = self.version.lower().strip()
        return f"{n}@{v}" if v else n

    @property
    def has_purl(self) -> bool:
        return bool(self.purl)

    @property
    def has_license(self) -> bool:
        return bool(self.licenses) and any(
            l not in ("NOASSERTION", "NONE", "", "unknown") for l in self.licenses
        )

    @property
    def has_sha512(self) -> bool:
        return any(k.upper() in ("SHA-512", "SHA512") for k in self.hashes)

    @property
    def has_any_hash(self) -> bool:
        return bool(self.hashes)

    @property
    def has_supplier(self) -> bool:
        return bool(self.supplier)


@dataclass
class SBOM:
    source_file: str
    format: str          # "cyclonedx" | "spdx-json" | "spdx-tv"
    spec_version: str
    components: list[Component] = field(default_factory=list)
    tool: str = ""

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def identities(self) -> set[str]:
        return {c.identity for c in self.components}

    @property
    def names(self) -> set[str]:
        return {c.name.lower().strip() for c in self.components}

    def coverage(self, attr: str) -> float:
        if not self.components:
            return 0.0
        return sum(1 for c in self.components if getattr(c, attr)) / len(self.components)


# ── Parsers ───────────────────────────────────────────────────────────────────

def _normalise_license(expr: str) -> str:
    if not expr:
        return ""
    return expr.strip().upper().replace("LICENSEREF-", "LicenseRef-")


def parse_cyclonedx(path: str) -> SBOM:
    with open(path) as f:
        data = json.load(f)

    spec = data.get("specVersion", "")
    tool_name = ""
    meta = data.get("metadata", {})
    for t in meta.get("tools", {}).get("components", meta.get("tools", [])):
        if isinstance(t, dict):
            tool_name = t.get("name", "")
            break

    components = []
    for raw in data.get("components", []):
        hashes = {}
        for h in raw.get("hashes", []):
            hashes[h.get("alg", "").upper()] = h.get("content", "")

        licenses = []
        for lic in raw.get("licenses", []):
            if "license" in lic:
                lic_id = lic["license"].get("id") or lic["license"].get("name", "")
                licenses.append(_normalise_license(lic_id))
            elif "expression" in lic:
                licenses.append(_normalise_license(lic["expression"]))

        supplier = ""
        for field_name in ("supplier", "publisher", "manufacturer"):
            val = raw.get(field_name)
            if val:
                supplier = val.get("name", "") if isinstance(val, dict) else str(val)
                break

        components.append(Component(
            name=raw.get("name", ""),
            version=raw.get("version", ""),
            purl=raw.get("purl", ""),
            licenses=licenses,
            hashes=hashes,
            supplier=supplier,
        ))

    return SBOM(
        source_file=os.path.basename(path),
        format="cyclonedx",
        spec_version=spec,
        components=components,
        tool=tool_name,
    )


def parse_spdx_json(path: str) -> SBOM:
    with open(path) as f:
        data = json.load(f)

    spec = data.get("spdxVersion", "")
    tool_name = ""
    for ci in data.get("creationInfo", {}).get("creators", []):
        if ci.startswith("Tool:"):
            tool_name = ci[5:].strip()
            break

    components = []
    for pkg in data.get("packages", []):
        spdxid = pkg.get("SPDXID", "")
        if spdxid == "SPDXRef-DOCUMENT":
            continue

        hashes = {}
        for chk in pkg.get("checksums", []):
            hashes[chk.get("algorithm", "").upper()] = chk.get("checksumValue", "")

        licenses = []
        for lf in ("licenseConcluded", "licenseDeclared"):
            val = pkg.get(lf, "")
            if val and val not in ("NOASSERTION", "NONE"):
                licenses.append(_normalise_license(val))

        purl = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceCategory") == "PACKAGE-MANAGER" and \
               ref.get("referenceType", "").startswith("purl"):
                purl = ref.get("referenceLocator", "")
                break

        supplier = pkg.get("supplier", "")
        if supplier in ("NOASSERTION", ""):
            supplier = ""

        components.append(Component(
            name=pkg.get("name", ""),
            version=pkg.get("versionInfo", ""),
            purl=purl,
            licenses=licenses,
            hashes=hashes,
            supplier=supplier,
        ))

    return SBOM(
        source_file=os.path.basename(path),
        format="spdx-json",
        spec_version=spec,
        components=components,
        tool=tool_name,
    )


def parse_spdx_tv(path: str) -> SBOM:
    """Parse SPDX tag-value format (.spdx files)."""
    spec = ""
    tool_name = ""
    components = []
    current: Optional[dict] = None

    def flush(pkg: Optional[dict]) -> Optional[Component]:
        if pkg is None:
            return None
        spdxid = pkg.get("SPDXID", "")
        if spdxid in ("SPDXRef-DOCUMENT", ""):
            return None

        hashes = {}
        for chk in pkg.get("checksums", []):
            alg, _, val = chk.partition(":")
            hashes[alg.strip().upper()] = val.strip()

        licenses = []
        for lf in ("LicenseConcluded", "LicenseDeclared"):
            val = pkg.get(lf, "")
            if val and val not in ("NOASSERTION", "NONE"):
                licenses.append(_normalise_license(val))

        supplier = pkg.get("PackageSupplier", "")
        if supplier in ("NOASSERTION", ""):
            supplier = ""
        # Strip "Organization:" or "Person:" prefix
        for prefix in ("Organization:", "Person:", "Tool:"):
            if supplier.startswith(prefix):
                supplier = supplier[len(prefix):].strip()
                break

        return Component(
            name=pkg.get("PackageName", ""),
            version=pkg.get("PackageVersion", ""),
            purl=pkg.get("ExternalRef_purl", ""),
            licenses=licenses,
            hashes=hashes,
            supplier=supplier,
        )

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")

            # Document-level fields
            if line.startswith("SPDXVersion:"):
                spec = line.split(":", 1)[1].strip()
                continue
            if line.startswith("Creator: Tool:"):
                tool_name = line.split(":", 2)[2].strip()
                continue

            # Package boundary
            if line.startswith("PackageName:"):
                if current is not None:
                    c = flush(current)
                    if c:
                        components.append(c)
                current = {}
                current["PackageName"] = line.split(":", 1)[1].strip()
                continue

            if current is None:
                continue

            if line.startswith("SPDXID:"):
                current["SPDXID"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageVersion:"):
                current["PackageVersion"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageChecksum:"):
                current.setdefault("checksums", []).append(line.split(":", 1)[1].strip())
            elif line.startswith("LicenseConcluded:"):
                current["LicenseConcluded"] = line.split(":", 1)[1].strip()
            elif line.startswith("LicenseDeclared:"):
                current["LicenseDeclared"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageSupplier:"):
                current["PackageSupplier"] = line.split(":", 1)[1].strip()
            elif line.startswith("ExternalRef:"):
                parts = line.split(":", 1)[1].strip().split()
                # PACKAGE-MANAGER purl pkg:...
                if len(parts) >= 3 and parts[0] == "PACKAGE-MANAGER" and \
                   parts[1].lower() == "purl":
                    current["ExternalRef_purl"] = parts[2]

    # Flush last package
    if current is not None:
        c = flush(current)
        if c:
            components.append(c)

    return SBOM(
        source_file=os.path.basename(path),
        format="spdx-tv",
        spec_version=spec,
        components=components,
        tool=tool_name,
    )


def load_sbom(path: str) -> SBOM:
    p = path.lower()
    if p.endswith(".spdx"):
        return parse_spdx_tv(path)
    try:
        with open(path) as f:
            data = json.load(f)
        if "bomFormat" in data:
            return parse_cyclonedx(path)
        if "spdxVersion" in data or "packages" in data:
            return parse_spdx_json(path)
    except json.JSONDecodeError:
        # Might be SPDX tag-value with a .json-looking extension
        return parse_spdx_tv(path)
    raise ValueError(f"Unrecognised SBOM format: {path}")


# ── Comparison ────────────────────────────────────────────────────────────────

@dataclass
class ComparisonResult:
    project: str
    generated_file: str
    official_file: str
    official_format: str
    official_spec: str
    generated_format: str
    generated_spec: str

    # Counts
    generated_count: int = 0
    official_count: int = 0
    count_delta: int = 0          # generated - official

    # Coverage metrics (0.0–1.0)
    generated_purl_cov: float = 0.0
    official_purl_cov: float = 0.0
    generated_license_cov: float = 0.0
    official_license_cov: float = 0.0
    generated_hash_cov: float = 0.0
    official_hash_cov: float = 0.0
    generated_sha512_cov: float = 0.0
    official_sha512_cov: float = 0.0
    generated_supplier_cov: float = 0.0
    official_supplier_cov: float = 0.0

    # Overlap
    overlap_by_name: int = 0      # names present in both
    only_in_official: list[str] = field(default_factory=list)   # names missing from generated
    only_in_generated: list[str] = field(default_factory=list)  # names extra in generated
    name_overlap_pct: float = 0.0  # official names covered by generated (recall)

    # Notable gaps
    missing_purls_sample: list[str] = field(default_factory=list)
    extra_components_sample: list[str] = field(default_factory=list)


def compare(project: str, generated: SBOM, official: SBOM) -> ComparisonResult:
    gen_names = generated.names
    off_names = official.names

    overlap = gen_names & off_names
    only_off = sorted(off_names - gen_names)
    only_gen = sorted(gen_names - off_names)

    recall = len(overlap) / len(off_names) if off_names else 0.0

    # Components in official that are missing PURLs in generated
    gen_by_name = {c.name.lower(): c for c in generated.components}
    missing_purls = [
        name for name in sorted(off_names & gen_names)
        if not gen_by_name.get(name, Component(name=name)).has_purl
    ][:20]

    return ComparisonResult(
        project=project,
        generated_file=generated.source_file,
        official_file=official.source_file,
        official_format=official.format,
        official_spec=official.spec_version,
        generated_format=generated.format,
        generated_spec=generated.spec_version,
        generated_count=generated.component_count,
        official_count=official.component_count,
        count_delta=generated.component_count - official.component_count,
        generated_purl_cov=generated.coverage("has_purl"),
        official_purl_cov=official.coverage("has_purl"),
        generated_license_cov=generated.coverage("has_license"),
        official_license_cov=official.coverage("has_license"),
        generated_hash_cov=generated.coverage("has_any_hash"),
        official_hash_cov=official.coverage("has_any_hash"),
        generated_sha512_cov=generated.coverage("has_sha512"),
        official_sha512_cov=official.coverage("has_sha512"),
        generated_supplier_cov=generated.coverage("has_supplier"),
        official_supplier_cov=official.coverage("has_supplier"),
        overlap_by_name=len(overlap),
        only_in_official=only_off[:50],
        only_in_generated=only_gen[:50],
        name_overlap_pct=recall,
        missing_purls_sample=missing_purls,
        extra_components_sample=only_gen[:20],
    )


# ── Report rendering ──────────────────────────────────────────────────────────

def pct(v: float) -> str:
    return f"{v*100:.1f}%"


def delta_str(n: int) -> str:
    if n > 0:
        return f"+{n}"
    return str(n)


BAR_WIDTH = 20


def bar(v: float) -> str:
    filled = round(v * BAR_WIDTH)
    return "[" + "█" * filled + "░" * (BAR_WIDTH - filled) + "]"


def render_text(results: list[ComparisonResult]) -> str:
    lines = []
    lines.append("=" * 80)
    lines.append("  transparenz SBOM Comparison Report — Generated vs Official Published")
    lines.append("=" * 80)
    lines.append("")

    for r in results:
        lines.append(f"┌─ {r.project.upper()} {'─' * max(0, 60 - len(r.project))}")
        lines.append(f"│  Generated : {r.generated_file}  ({r.generated_format} {r.generated_spec})")
        lines.append(f"│  Official  : {r.official_file}  ({r.official_format} {r.official_spec})")
        lines.append("│")
        lines.append(f"│  Components")
        lines.append(f"│    Generated : {r.generated_count:>5}")
        lines.append(f"│    Official  : {r.official_count:>5}")
        lines.append(f"│    Delta     : {delta_str(r.count_delta):>5}  "
                     f"({'over' if r.count_delta > 0 else 'under'}-counts official)")
        lines.append("│")
        lines.append(f"│  Name overlap (recall — official packages found in generated)")
        lines.append(f"│    {bar(r.name_overlap_pct)} {pct(r.name_overlap_pct)}"
                     f"  ({r.overlap_by_name}/{r.official_count} official packages)")
        lines.append("│")
        lines.append(f"│  Coverage comparison        Generated          Official")
        lines.append(f"│  {'─'*56}")

        metrics = [
            ("PURL",     r.generated_purl_cov,     r.official_purl_cov),
            ("License",  r.generated_license_cov,  r.official_license_cov),
            ("Any hash", r.generated_hash_cov,     r.official_hash_cov),
            ("SHA-512",  r.generated_sha512_cov,   r.official_sha512_cov),
            ("Supplier", r.generated_supplier_cov, r.official_supplier_cov),
        ]
        for label, gen_v, off_v in metrics:
            diff = gen_v - off_v
            diff_icon = "▲" if diff > 0.01 else ("▼" if diff < -0.01 else "≈")
            lines.append(
                f"│  {label:<10}  {bar(gen_v)} {pct(gen_v):>6}    "
                f"{bar(off_v)} {pct(off_v):>6}  {diff_icon} {delta_str(round(diff*100))}pp"
            )

        lines.append("│")
        if r.only_in_official:
            lines.append(f"│  Packages in official NOT in generated ({len(r.only_in_official)} shown, "
                         f"{len(r.only_in_official)} total):")
            for name in r.only_in_official[:15]:
                lines.append(f"│    - {name}")
            if len(r.only_in_official) > 15:
                lines.append(f"│    … and {len(r.only_in_official) - 15} more")
        else:
            lines.append("│  Packages in official NOT in generated: none ✓")

        lines.append("│")
        if r.only_in_generated:
            lines.append(f"│  Packages in generated NOT in official ({len(r.only_in_generated)} shown):")
            for name in r.only_in_generated[:10]:
                lines.append(f"│    + {name}")
            if len(r.only_in_generated) > 10:
                lines.append(f"│    … and {len(r.only_in_generated) - 10} more")
        else:
            lines.append("│  Packages in generated NOT in official: none")

        if r.missing_purls_sample:
            lines.append("│")
            lines.append(f"│  Matched packages missing PURLs in generated ({len(r.missing_purls_sample)}):")
            for name in r.missing_purls_sample[:10]:
                lines.append(f"│    ✗ {name}")

        lines.append("└" + "─" * 78)
        lines.append("")

    # ── Summary table ──────────────────────────────────────────────────────
    lines.append("=" * 80)
    lines.append("  SUMMARY TABLE")
    lines.append("=" * 80)
    hdr = (
        f"{'Project':<20} {'Gen':>5} {'Off':>5} {'Δ':>5}  "
        f"{'Recall':>7}  {'PURL%':>6}  {'Lic%':>6}  {'SHA512%':>8}  {'Suppl%':>7}"
    )
    lines.append(hdr)
    lines.append("─" * 80)
    for r in results:
        lines.append(
            f"{r.project:<20} {r.generated_count:>5} {r.official_count:>5} "
            f"{delta_str(r.count_delta):>5}  "
            f"{pct(r.name_overlap_pct):>7}  "
            f"{pct(r.generated_purl_cov):>6}  "
            f"{pct(r.generated_license_cov):>6}  "
            f"{pct(r.generated_sha512_cov):>8}  "
            f"{pct(r.generated_supplier_cov):>7}"
        )
    lines.append("")
    lines.append("Legend: Gen=generated components, Off=official components, Δ=Gen-Off,")
    lines.append("        Recall=% of official packages found in generated SBOM,")
    lines.append("        PURL%/Lic%/SHA512%/Suppl% = coverage in generated SBOM")
    lines.append("")

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

# Map: project slug → (generated_sbom_path, [official_sbom_paths])
# Multiple official files are merged (e.g. argo-cd has 3 SPDX files)
REPO_ROOT = Path(__file__).parent.parent
SBOM_DIR = REPO_ROOT / "test-results" / "sbom-100" / "sboms"
OFFICIAL_DIR = REPO_ROOT / "test-results" / "sbom-100" / "official"

COMPARISONS = {
    "kubernetes": (
        SBOM_DIR / "kubernetes.json",
        [OFFICIAL_DIR / "kubernetes-official.spdx"],
    ),
    "istio": (
        SBOM_DIR / "istio.json",
        [OFFICIAL_DIR / "istio-official.spdx"],
    ),
    "argo-cd": (
        SBOM_DIR / "argo-cd.json",
        # use go-mod SBOM as the most comparable (source deps, not container image)
        [OFFICIAL_DIR / "bom-go-mod.spdx"],
    ),
    "flux": (
        SBOM_DIR / "flux.json",
        [OFFICIAL_DIR / "flux-official.spdx.json"],
    ),
    "caddy": (
        SBOM_DIR / "caddy.json",
        [OFFICIAL_DIR / "caddy-official.cdx.json"],
    ),
    "trivy": (
        SBOM_DIR / "trivy.json",
        [OFFICIAL_DIR / "trivy-official.cdx.json"],
    ),
}


def merge_sboms(sboms: list[SBOM]) -> SBOM:
    """Merge multiple official SBOMs into one for comparison (deduplicate by identity)."""
    if len(sboms) == 1:
        return sboms[0]
    seen = set()
    merged_components = []
    for s in sboms:
        for c in s.components:
            if c.identity not in seen:
                seen.add(c.identity)
                merged_components.append(c)
    base = sboms[0]
    return SBOM(
        source_file=" + ".join(s.source_file for s in sboms),
        format=base.format,
        spec_version=base.spec_version,
        components=merged_components,
        tool=base.tool,
    )


def main():
    parser = argparse.ArgumentParser(description="Compare generated vs official SBOMs")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "test-results" / "sbom-100" / "comparison"))
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON summary")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    errors = []

    for project, (gen_path, off_paths) in COMPARISONS.items():
        if not gen_path.exists():
            errors.append(f"  SKIP {project}: generated SBOM not found at {gen_path}")
            continue
        missing_off = [p for p in off_paths if not p.exists()]
        if missing_off:
            errors.append(f"  SKIP {project}: official SBOM(s) not found: {missing_off}")
            continue

        try:
            generated = load_sbom(str(gen_path))
            officials = [load_sbom(str(p)) for p in off_paths]
            official = merge_sboms(officials)
            result = compare(project, generated, official)
            results.append(result)

            # Write per-project JSON detail
            detail_path = output_dir / f"{project}-comparison.json"
            with open(detail_path, "w") as f:
                json.dump(asdict(result), f, indent=2)

        except Exception as e:
            errors.append(f"  ERROR {project}: {e}")

    if errors:
        print("Warnings / Skips:", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        print(render_text(results))

    # Write full JSON report regardless
    report_path = output_dir / "comparison-report.json"
    with open(report_path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"Full JSON report: {report_path}", file=sys.stderr)

    # Exit 1 if recall < 50% on any project
    low_recall = [r for r in results if r.name_overlap_pct < 0.5]
    if low_recall:
        print(f"WARNING: {len(low_recall)} project(s) have recall < 50%: "
              f"{[r.project for r in low_recall]}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
