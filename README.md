# baseline_security-conytrol

What this repo demonstrates

SBOM generation using CycloneDX

Vulnerability detection using Trivy

Risk-based enforcement using OPA (policy-as-code)

CI/CD security gates using GitHub Actions

Enterprise-style exception handling
it is a baseline security control.
###########################################################################################################################################################
sbom-vulnerability-gates/
│
├── .github/
│   └── workflows/
│       └── security-pipeline.yml
│
├── policy/
│   └── vulnerability.rego
│
├── exceptions/
│   └── approved-exceptions.json
│
├── scripts/
│   └── generate_sbom.sh
│
├── Dockerfile
├── README.md
└── .gitignore
