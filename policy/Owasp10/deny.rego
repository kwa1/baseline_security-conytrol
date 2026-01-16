package owasp.deny

import data.owasp.severity.blocked_categories
import data.owasp.metadata.owasp_categories
import data.owasp.exceptions.allowed
import data.owasp.controls.owasp_to_controls

deny[msg] {
  finding := input.findings[_]
  finding.owasp in blocked_categories

  not allowed with input.finding as finding

  controls := owasp_to_controls[finding.owasp]

  msg := sprintf(
    "OWASP %s (%s) blocked | ISO=%v | NIST=%v | Package=%s | Severity=%s",
    [
      finding.owasp,
      owasp_categories[finding.owasp],
      controls.iso,
      controls.nist,
      finding.package,
      finding.severity
    ]
  )
}
