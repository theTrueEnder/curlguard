# Security Policy

## Reporting Vulnerabilities

If you find a security issue in curlguard, please report it responsibly.

**Do NOT** open a public GitHub issue for security vulnerabilities.

A private reporting channel has not yet been established. Do not send sensitive
reports to the former placeholder address.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Scope

curlguard is a user-space wrapper. It does NOT:
- Modify the Linux kernel
- Intercept network traffic at the OSI layer
- Execute code outside the scanned file's intended flow

## Known Limitations

- YARA findings and no-match results are not proof of artifact safety or authenticity
- Remote rule updates require signed bundles and independently provisioned public keys
- PATH wrappers and user-controlled settings are voluntary protection, not organizational enforcement
- Artifact publisher-signature verification is not implemented
- curlguard cannot detect malware that is obfuscated beyond its YARA rules