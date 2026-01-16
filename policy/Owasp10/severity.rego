package owasp.severity

default blocked_categories := []

blocked_categories := ["A03", "A05", "A06"] {
  input.environment == "prod"
}

blocked_categories := ["A03", "A05"] {
  input.environment == "staging"
}

blocked_categories := [] {
  input.environment == "dev"
}
