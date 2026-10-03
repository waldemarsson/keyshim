# Security policy

Fullmakt handles credentials, so security reports are welcome and taken
seriously.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue, pull request or discussion for a vulnerability.

Include what you can of:

- the version (`fullmakt version`) and operating system
- the configuration involved, with secret values, tokens and hostnames you
  consider sensitive removed
- steps to reproduce, and what an attacker gains

This is a personal open source project maintained in spare time. Reports are
read and handled on a best-effort basis, without a guaranteed response time.

## Supported versions

Only the latest release receives security fixes.

## Scope

The security model in the [README](README.md#security-model) describes what
fullmakt guarantees and what it does not. Reports about the listed
non-guarantees, for example an agent using a secret for a request that a rule
allows, are expected behaviour rather than vulnerabilities, but suggestions
for hardening are still welcome.

## No warranty

Fullmakt is provided "as is", without warranty of any kind, under the
[Apache License 2.0](LICENSE). See sections 7 and 8 of the license.
