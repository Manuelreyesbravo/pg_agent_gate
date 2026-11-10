# pg_agent_gate on Red Hat Enterprise Linux

LatamFlows ships pg_agent_gate for Red Hat Enterprise Linux as **ygg-pg Enterprise**:
a container image built on Red Hat's PostgreSQL 18 image (`rhel9/postgresql-18`), with
pg_agent_gate 0.4.1, pg_living_assertions 0.5.10, pg_promise_guard 0.2.9 and
pg_grammar_guard 0.4.9.

## Supported platforms

| Product version | Red Hat platform |
|---|---|
| ygg-pg Enterprise 0.3.0 | Red Hat Enterprise Linux 9 (9.0 – 9.9), with Podman |

- Tested on Red Hat Enterprise Linux 9.8 (kernel 5.14.0-687.59.1.el9_8), SELinux
  enforcing, Podman 5.8.5: 33 of 33 image checks passed (2026-11-10).
- Runs as a non-root user (uid 26); does not require SELinux to be disabled.
- Red Hat OpenShift: not yet tested.

LatamFlows is a Red Hat partner; container certification is the next step.

Support: manu@latamflows.com
