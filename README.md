# AC-Hunter-Zeek-Log-Transport

modified from https://github.com/activecm/zeek-log-transport/tree/master

Modifications from the original v0.4.1:

- Excludes the `current` directory from transfer
- Flattens the directory structure with a date prefix (e.g. `2026-01-25_conn.log.gz`), as RITA rolling import requires a flat structure
- Adds `StrictHostKeyChecking=accept-new` to the ssh parameters, so the first non-interactive run from cron does not fail on an unknown host key (a changed host key is still refused)
