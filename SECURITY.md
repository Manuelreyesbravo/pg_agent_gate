# Security

pg_agent_gate is a security boundary, so a way around it is the most valuable
report this project can receive.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately, by either:

* GitHub's private vulnerability reporting: the **Security** tab of this
  repository, then **Report a vulnerability**; or
* email to **manuelreyesbravo@gmail.com**, subject starting with
  `[pg_agent_gate security]`.

Please include the PostgreSQL version, the pg_agent_gate version (`SELECT
agent_gate.whoami()` and `SELECT extversion FROM pg_extension WHERE extname =
'pg_agent_gate'`), and the smallest sequence of statements that shows it. A case
in the style of `tests/*.sh` -- an attack plus a superuser's check that something
changed -- is ideal, because it becomes the regression test.

You will get an acknowledgement within 72 hours. A confirmed bypass is fixed
before it is disclosed, gets a regression case in `tests/`, and is credited to
you in the CHANGELOG unless you prefer otherwise.

## What counts

Anything that lets a session registered as an agent execute SQL other than the
gate's verbs, get a proposal past verification that should not pass, change
more rows than its `max_rows`, move the context its row-level policies read,
or alter the record. The [threat model](README.md#threat-model) says what is in
scope; what it lists as trusted or not covered is known, but a clearer way to
explain it is welcome too.

## Supported versions

The latest release. Fixes are not backported while the project is pre-1.0.
