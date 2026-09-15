# Security Policy

## Reporting a vulnerability

Email **security@kalmpass.net**. Please do not open a public issue for anything
exploitable.

Include what you found, how to reproduce it, and what you think the impact is. We
will acknowledge within 72 hours, keep you updated, and credit you in the fix
notes if you would like that.

Testing against your own account is welcome, provided you do not degrade the
service for others and do not access anyone else's data. We will never respond to
a good-faith report with legal threats.

## Scope

In scope: the Worker (`src/`), the client (`public/js/`), the schema, the
security headers, and the cryptographic design itself.

Out of scope: findings that require a compromised device, missing headers on
static marketing pages with no dynamic content, and the inherent trust placed in
a web-delivered application, which is documented openly in the README.

## What we consider serious

Anything that would let a party other than the account holder read vault
contents. That includes any path by which the server, an attacker holding the
database, or an attacker holding `SERVER_KEY` could recover plaintext. The design
intends all three to be impossible; a demonstration that any of them is not is
the most valuable report we could receive.
