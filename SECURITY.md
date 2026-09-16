# Security and Responsible Use

Dreambox Scanner is designed for diagnostics on networks and devices you own or are explicitly authorized to administer.

## Scope safeguards

Version 6 accepts IPv4 targets only from private, loopback and link-local ranges:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `169.254.0.0/16`

Public Internet targets are intentionally rejected. The scanner also limits the maximum expanded target set to 4096 hosts and caps host concurrency at 128 workers.

## Credentials

Do not store passwords in source files or shell history. When HTTP authentication is needed, provide the username with `--username` and place the password in the environment variable selected with `--password-env` (default: `DREAMBOX_SCANNER_PASSWORD`).

## Reporting a security issue

Please report security-sensitive problems privately to the repository owner rather than publishing credentials, private network details or exploitable device information in a public issue.
