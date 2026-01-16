import json
import argparse

OWASP_MAPPING = {
    "Injection": "A03",
    "SQL Injection": "A03",
    "Command Injection": "A03",
    "Cross-Site Scripting": "A03",

    "Misconfiguration": "A05",
    "Default Credential": "A05",
    "Improper Configuration": "A05",

    "Cryptographic": "A02",
    "Weak Encryption": "A02",
    "Hardcoded Secret": "A02",

    "Vulnerable Component": "A06",
    "Outdated Library": "A06",

    "Integrity": "A08",
    "Untrusted Source": "A08",
}

DEFAULT_CATEGORY = "A06"

CONTROL_MAP = {
    "A01": {"iso": ["A.9.1", "A.9.4"], "nist": ["AC-3", "AC-6"]},
    "A02": {"iso": ["A.10.1"], "nist": ["SC-12", "SC-13"]},
    "A03": {"iso": ["A.14.2.5"], "nist": ["SI-10"]},
    "A05": {"iso": ["A.12.1", "A.12.5"], "nist": ["CM-2", "CM-6"]},
    "A06": {"iso": ["A.12.6"], "nist": ["SI-2"]},
    "A08": {"iso": ["A.14.2.8"], "nist": ["SI-7"]}
}


def map_to_owasp(vuln):
    text = f"{vuln.get('Title','')} {vuln.get('Description','')}"
    for keyword, owasp in OWASP_MAPPING.items():
        if keyword.lower() in text.lower():
            return owasp
    return DEFAULT_CATEGORY


def analyze(input_file, output_file, environment):
    with open(input_file) as f:
        report = json.load(f)

    findings = []

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            owasp = map_to_owasp(vuln)
            findings.append({
                "id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "severity": vuln.get("Severity"),
                "owasp": owasp,
                "controls": CONTROL_MAP.get(owasp, {})
            })

    output = {
        "environment": environment,
        "summary": {
            k: sum(1 for f in findings if f["owasp"] == k)
            for k in set(f["owasp"] for f in findings)
        },
        "findings": findings
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[+] OWASP analysis written to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--environment", required=True)

    args = parser.parse_args()
    analyze(args.input, args.output, args.environment)
