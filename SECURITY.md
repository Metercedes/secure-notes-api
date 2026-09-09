# Security policy

This is a portfolio project, not a deployed service, and it holds no real user data.

If you find a security problem in the code, please open an issue describing the affected file and
the conditions required to trigger it. Since there is nothing running to exploit, public disclosure
is fine and is more useful than a private report.

## Scope

In scope: authentication, authorisation, token handling, input validation, dependency
vulnerabilities, and anything in `docs/threat-model.md` claimed as a control that is not actually
enforced by the code.

Out of scope: the known limitations listed in `docs/threat-model.md`. Those are documented
trade-offs rather than oversights.

## Supported versions

The `main` branch only.
