package security.environment

import data.security.metadata

default deny = []

deny[msg] {
    not input.environment
    msg := "Environment not provided to policy engine"
}

deny[msg] {
    input.environment not in metadata.required_environment
    msg := sprintf(
        "Invalid environment '%s'. Allowed: %v",
        [input.environment, metadata.required_environment]
    )
}
