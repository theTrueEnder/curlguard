# Security Policy

## Reporting Vulnerabilities

If you find a security issue in curlguard, please report it responsibly.

**Do NOT** open a public GitHub issue for security vulnerabilities.

Use the repository's private
[Security → Report a vulnerability](https://github.com/theTrueEnder/curlguard/security/advisories/new)
workflow.

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

- YARA rules must be pre-compiled; very large rulesets may impact performance
- Auto-update fetches rules from configured URL — ensure the source is trusted
- curlguard cannot detect malware that is obfuscated beyond its YARA rules
