package owasp.exceptions

import future.keywords.if

default allowed := false

allowed {
  exception := input.exceptions[_]
  exception.owasp == input.finding.owasp
  not expired(exception.expires)
}

expired(date) {
  now := time.now_ns()
  expiry := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [date]))
  expiry < now
}
