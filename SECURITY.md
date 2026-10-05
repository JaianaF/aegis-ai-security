# Security and authorized-use policy

AegisAI Security is intended for defensive testing of systems you own or are explicitly authorized to assess.

## Safety defaults

- Local/private network targets are blocked unless `ALLOW_PRIVATE_TARGETS=true` is explicitly set for an authorized lab.
- Authentication headers supplied for a scan are ephemeral and are not persisted.
- Detected secrets and PII are redacted from stored evidence.
- Built-in probes are non-destructive: they do not intentionally execute commands, modify data, bypass authentication, or persist payloads.
- Redirects are not followed by the scanner.

## Reporting a vulnerability in AegisAI Security

Do not place real credentials or sensitive customer data in a public issue. Reproduce with synthetic data whenever possible.
