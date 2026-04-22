# Security Policy

## Supported Version

Security fixes are currently applied to the latest version in this repository.

## Reporting A Vulnerability

- Do not include API keys, private URLs, or account data in a public issue.
- Prefer a private GitHub security advisory if the repository has that feature enabled.
- If private reporting is not available yet, open an issue with sensitive details removed and enough information to reproduce the problem safely.

## Current Security Model

- The extension stores the VirusTotal API key in the browser extension's local storage area.
- Requests are sent directly to VirusTotal from the extension.
- The UI renders remote strings with `textContent`, not HTML injection APIs.
- The extension only processes `http` and `https` page URLs.
