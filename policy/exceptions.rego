package security.exceptions

default allow = false

allow {
    some e
    e := data.exceptions.exceptions[_]
    e.vulnerability_id == input.VulnerabilityID
    e.expires_at > time.now_ns()
}
