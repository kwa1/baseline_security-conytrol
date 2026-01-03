#!/usr/bin/env python3
"""
Send SBOM & Vulnerability metrics to CloudWatch
"""
import json
import argparse
import boto3

def send_metric(name: str, value: float, namespace="CI/CD/Security"):
    client = boto3.client("cloudwatch")
    response = client.put_metric_data(
        Namespace=namespace,
        MetricData=[{
            'MetricName': name,
            'Value': value,
            'Unit': 'Count'
        }]
    )
    return response

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vuln-report", required=True)
    parser.add_argument("--mitre-report", required=True)
    args = parser.parse_args()

    with open(args.vuln_report, "r") as f:
        vuln_report = json.load(f)
    with open(args.mitre_report, "r") as f:
        mitre_report = json.load(f)

    # Count vulnerabilities by severity
    critical = sum(len(r.get("Vulnerabilities", [])) for r in vuln_report.get("Results", []) 
                   if any(v["Severity"]=="CRITICAL" for v in r.get("Vulnerabilities", [])))
    high = sum(len(r.get("Vulnerabilities", [])) for r in vuln_report.get("Results", []) 
               if any(v["Severity"]=="HIGH" for v in r.get("Vulnerabilities", [])))

    # Count MITRE attack chains
    attack_chains = len(mitre_report.get("attack_chains", []))

    # Send to CloudWatch
    send_metric("Vulnerabilities_Critical", critical)
    send_metric("Vulnerabilities_High", high)
    send_metric("MITRE_Attack_Chains", attack_chains)

    print(f"Metrics sent to CloudWatch: CRITICAL={critical}, HIGH={high}, Attack Chains={attack_chains}")

if __name__ == "__main__":
    main()
