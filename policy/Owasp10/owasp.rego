#
*/*
package security.owasp

import data.security.common

# OWASP Top 10 mapping (example)
owasp_risk_map := {
  "A1:2021-Broken Access Control": ["privilege_escalation", "auth_bypass"],
  "A2:2021-Cryptographic Failures": ["data_exposure", "weak_crypto"],
  "A3:2021-Injection": ["sql_injection", "command_injection"],
  "A4:2021-Insecure Design": ["logic_flaw", "misconfig"],
  "A5:2021-Security Misconfiguration": ["misconfig"],
  "A6:2021-Vulnerable and Outdated Components": ["unpatched_library", "known_cve"],
  "A7:2021-Identification and Authentication Failures": ["auth_bypass"],
  "A8:2021-Software and Data Integrity Failures": ["untrusted_deserialization"],
  "A9:2021-Security Logging and Monitoring Failures": ["missing_audit"],
  "A10:2021-Server-Side Request Forgery (SSRF)": ["ssrf"]
}

# Deny input if it triggers OWASP top 10 risks
deny[msg] {
  result := input.Results[_]
  vuln := result.Vulnerabilities[_]

  # Ignore approved exceptions
  not common.approved_cve(vuln.VulnerabilityID)

  # Map CVE / description to OWASP risk categories
  risk_category := map_to_owasp(vuln)
  risk_category != ""

  severity := common.severity_rank[vuln.Severity]
  severity >= common.deny_threshold(input.environment)

  msg := sprintf(
    "OWASP Violation: %s in %s triggers %s (Severity: %s)",
    [vuln.VulnerabilityID, result.Target, risk_category, vuln.Severity]
  )
}

# Simple mapping function: description -> OWASP risk
map_to_owasp(vuln) = risk {
  desc := lower(vuln.Description)

  risk := "A3:2021-Injection" {
    contains(desc, "sql injection") 
    or contains(desc, "command injection") 
    or contains(desc, "rce")
  }

  risk := "A6:2021-Vulnerable and Outdated Components" {
    contains(desc, "unpatched") 
    or contains(desc, "library")
  }

  risk := "A5:2021-Security Misconfiguration" {
    contains(desc, "misconfiguration") 
    or contains(desc, "default password")
  }

  risk := "A1:2021-Broken Access Control" {
    contains(desc, "privilege escalation") 
    or contains(desc, "unauthorized")
  }

  # default to empty if no match
  risk := "" { not risk }
}
*/#