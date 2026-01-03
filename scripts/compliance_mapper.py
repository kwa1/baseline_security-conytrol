#!/usr/bin/env python3
"""
Compliance Mapper

Purpose:
- Map SBOM & vulnerability findings to selected compliance frameworks
- Generate JSON report compatible with CI/CD pipelines

Inputs:
- Trivy vulnerability report (vuln-report.json)
Outputs:
- Compliance report JSON
"""

import json
import argparse
from datetime import datetime
from typing import List, Dict, Any

# -----------------------------
# Compliance Mapping Definitions
# -----------------------------
FRAMEWORK_MAPPING = {
    "SLSA": {
        "LOW": ["SLSA.1.1", "SLSA.1.2"],
        "MEDIUM": ["SLSA.1.3"],
        "HIGH": ["SLSA.2.1", "SLSA.2.2"],
        "CRITICAL": ["SLSA.3.1"]
    },
    "NIST800-53": {
        "LOW": ["AC-2", "AU-2"],
        "MEDIUM": ["CM-6", "SI-2"],
        "HIGH": ["SC-7", "SI-3"],
        "CRITICAL": ["RA-5"]
    },
    "ISO27001": {
        "LOW": ["A.5.1", "A.6.1"],
        "MEDIUM": ["A.8.1", "A.12.1"],
        "HIGH": ["A.12.6", "A.14.2"],
        "CRITICAL": ["A.16.1"]
    }
}

# -----------------------------
# Analyzer
# -----------------------------
class ComplianceMapper:
    def __init__(self, frameworks: List[str]):
        self.frameworks = frameworks

    def map_findings(self, vuln_report: Dict[str, Any]) -> Dict[str, Any]:
        report = {"metadata": {}, "frameworks": {}}
        report["metadata"]["generated_at"] = datetime.utcnow().isoformat()
        report["metadata"]["frameworks"] = self.frameworks

        # Prepare framework-specific results
        for fw in self.frameworks:
            report["frameworks"][fw] = []

        for result in vuln_report.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN")
                component = result.get("Target", "unknown")
                vuln_id = vuln.get("VulnerabilityID", "unknown")

                for fw in self.frameworks:
                    mapped_controls = FRAMEWORK_MAPPING.get(fw, {}).get(sev, [])
                    if mapped_controls:
                        report["frameworks"][fw].append({
                            "component": component,
                            "vulnerability_id": vuln_id,
                            "severity": sev,
                            "mapped_controls": mapped_controls
                        })
        return report

# -----------------------------
# CLI
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Compliance Mapper")
    parser.add_argument("--input", required=True, help="Trivy vulnerability JSON file")
    parser.add_argument("--output", required=True, help="Output compliance JSON file")
    parser.add_argument("--frameworks", default="SLSA,NIST800-53,ISO27001",
                        help="Comma-separated list of frameworks")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        vuln_report = json.load(f)

    frameworks = [f.strip() for f in args.frameworks.split(",")]
    mapper = ComplianceMapper(frameworks)
    report = mapper.map_findings(vuln_report)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Compliance report generated: {args.output}")
    for fw in frameworks:
        count = len(report["frameworks"][fw])
        print(f"{fw}: {count} mapped findings")

if __name__ == "__main__":
    main()
