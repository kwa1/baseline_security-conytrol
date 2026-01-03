package security.mitre

import data.security.metadata

default deny = []

# Base risk threshold
base_threshold := 80

# Deny if any MITRE finding exceeds threshold in the current environment
deny[msg] {
    some f
    f := input.mitre_findings[_]

    # Threshold can be overridden per environment if needed
    threshold := base_threshold
    input.environment == "prod"
    f.risk_score >= threshold

    msg := sprintf(
        "[Policy %s][%s] MITRE technique(s) %v risk %d exceeds threshold",
        [metadata.policy_version, input.environment, f.mitre_techniques, f.risk_score]
    )
}
