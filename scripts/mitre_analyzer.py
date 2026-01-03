#!/usr/bin/env python3
"""
MITRE ATT&CK Vulnerability Analyzer (v1.3.0)

- Produces findings compatible with OPA mitre.rego
- Risk scoring and attack chains included
"""

import json
import argparse
from datetime import datetime
from typing import Dict, List, Any

# -----------------------------
# MITRE KNOWLEDGE (STATIC MAP)
# -----------------------------
MITRE_CVE_MAP = {
    "CVE-2021-44228": ["T1190", "T1059"],
    "CVE-2023-34362": ["T1190"],
    "CVE-2021-34527": ["T1068"],
    "CVE-2020-1472": ["T1068", "T1555"],
}

TECHNIQUE_TO_TACTIC = {
    "T1190": "initial_access",
    "T1059": "execution",
    "T1068": "privilege_escalation",
    "T1555": "credential_access",
    "T1485": "impact",
    "T1486": "impact",
}

# -----------------------------
# ANALYZER
# -----------------------------
class MITREAnalyzer:
    def __init__(self, environment: str):
        self.environment = environment

    def analyze(self, vuln_report: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        for result in vuln_report.get("Results", []):
            component = result.get("Target", "unknown")
            for vuln in result.get("Vulnerabilities", []):
                finding = self._analyze_vulnerability(vuln, component)
                if finding:
                    findings.append(finding)

        attack_chains = self._identify_attack_chains(findings)
        risk_assessment = self._assess_risk(findings, attack_chains)

        return {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "environment": self.environment,
                "analyzer_version": "v1.3.0"
            },
            "mitre_findings": findings,
            "attack_chains": attack_chains,
            "risk_assessment": risk_assessment
        }

    # -----------------------------
    # PER-VULNERABILITY ANALYSIS
    # -----------------------------
    def _analyze_vulnerability(self, vuln: Dict[str, Any], component: str) -> Dict[str, Any]:
        cve = vuln.get("VulnerabilityID")
        severity = vuln.get("Severity", "UNKNOWN")
        cvss = vuln.get("CVSS", {}).get("v3", {}).get("score", 0.0)
        description = vuln.get("Description", "")

        techniques = self._map_to_techniques(cve, description)
        if not techniques:
            return None

        tactics = list({TECHNIQUE_TO_TACTIC[t] for t in techniques if t in TECHNIQUE_TO_TACTIC})
        risk_score = self._calculate_risk(cvss, tactics)

        return {
            "VulnerabilityID": cve,
            "component": component,
            "severity": severity,
            "cvss": cvss,
            "mitre_techniques": techniques,
            "mitre_tactics": tactics,
            "risk_score": risk_score
        }

    # -----------------------------
    # MAPPING LOGIC
    # -----------------------------
    def _map_to_techniques(self, cve: str, description: str) -> List[str]:
        if cve in MITRE_CVE_MAP:
            return MITRE_CVE_MAP[cve]
        desc = description.lower()
        techniques = []
        if "remote code execution" in desc or "rce" in desc:
            techniques.append("T1190")
        if "privilege escalation" in desc:
            techniques.append("T1068")
        if "credential" in desc or "password" in desc:
            techniques.append("T1555")
        return techniques

    # -----------------------------
    # RISK CALCULATION
    # -----------------------------
    def _calculate_risk(self, cvss: float, tactics: List[str]) -> int:
        base = cvss * 10
        multiplier = 1.0
        if "initial_access" in tactics:
            multiplier = max(multiplier, 1.5)
        if "privilege_escalation" in tactics:
            multiplier = max(multiplier, 1.8)
        if "impact" in tactics:
            multiplier = max(multiplier, 2.0)
        return min(100, int(base * multiplier))

    # -----------------------------
    # ATTACK CHAIN DETECTION
    # -----------------------------
    def _identify_attack_chains(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        chains = []
        by_component: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            by_component.setdefault(f["component"], []).append(f)

        for component, vulns in by_component.items():
            tactics = {t for v in vulns for t in v["mitre_tactics"]}
            if "initial_access" in tactics and "privilege_escalation" in tactics:
                chains.append({
                    "component": component,
                    "vulnerabilities": [v["VulnerabilityID"] for v in vulns],
                    "tactics": list(tactics),
                    "chain_risk": max(v["risk_score"] for v in vulns)
                })
        return chains

    # -----------------------------
    # OVERALL RISK ASSESSMENT
    # -----------------------------
    def _assess_risk(self, findings: List[Dict[str, Any]], attack_chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        critical = [f for f in findings if f["risk_score"] >= 80]
        high = [f for f in findings if 60 <= f["risk_score"] < 80]

        level = "LOW"
        if critical or attack_chains:
            level = "HIGH"
        elif high:
            level = "MEDIUM"

        recommendations = []
        if critical:
            recommendations.append("Immediately remediate vulnerabilities enabling initial access or privilege escalation")
        if attack_chains:
            recommendations.append("Break identified attack chains by patching linked vulnerabilities")

        return {
            "overall_risk_level": level,
            "critical_findings": len(critical),
            "high_findings": len(high),
            "attack_chains_detected": len(attack_chains),
            "recommendations": recommendations
        }

# -----------------------------
# CLI
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Vulnerability Analyzer")
    parser.add_argument("--input", required=True, help="Trivy vulnerability JSON")
    parser.add_argument("--output", required=True, help="MITRE analysis output JSON")
    parser.add_argument("--environment", default="production")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        vuln_report = json.load(f)

    analyzer = MITREAnalyzer(environment=args.environment)
    analysis = analyzer.analyze(vuln_report)

    with open(args.output, "w") as f:
        json.dump(analysis, f, indent=2)

    print("MITRE analysis complete")
    print(f"Overall risk level: {analysis['risk_assessment']['overall_risk_level']}")

if __name__ == "__main__":
    main()
