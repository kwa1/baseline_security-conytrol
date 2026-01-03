package security.sbom

import data.security.metadata

default deny = []

# SBOM must be CycloneDX
deny[msg] {
    input.bomFormat != "CycloneDX"
    msg := sprintf(
        "[Policy %s] SBOM must be CycloneDX format",
        [metadata.policy_version]
    )
}

# SBOM must have components
deny[msg] {
    count(input.components) == 0
    msg := sprintf(
        "[Policy %s] SBOM contains no components",
        [metadata.policy_version]
    )
}

# Root component metadata required
deny[msg] {
    not input.metadata.component
    msg := sprintf(
        "[Policy %s] SBOM missing root component metadata",
        [metadata.policy_version]
    )
}
