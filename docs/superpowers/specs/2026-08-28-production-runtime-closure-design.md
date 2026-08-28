# A4Diag Production Runtime Closure Design

## Goal

Close the existing v0.4 production gaps without weakening policy, approval,
identity, ticket, audit, or rollback guarantees.

## Configuration

Every production command reads one strict settings-v3 document.  The document
stores model, notifications, alert source, plugin registry references and the
transport details required by each target.  Legacy `Config` remains available
only for old report/tests compatibility and is not used by `serve`, `cleanup`,
`init`, approvals, or runtime construction.

Non-interactive initialization may request write access only when the request
also contains the exact literal confirmation `ENABLE`.  The confirmation is
consumed during initialization and is never persisted as authority.

## Plugin execution

The workflow supplies the durable transaction id and step id to every effect
port.  RPC payloads bind transaction, step, operation, marker and undo data to
the operation ticket.  Socket-activated hosts consume the inherited systemd
socket; manually started hosts create a new socket and continue to reject an
unrelated pre-existing path.

Installed plugin artifacts, manifests, registry pins, instance configuration
and systemd instance names derive from one canonical plugin installation
layout.

## Approval and recovery

Runtime and CLI share the same state database paths.  `show` reads the plan
from the durable LangGraph checkpoint and transaction stores.  Successful CLI
approval resumes that same runtime transaction exactly once; an explicit
`a4diag resume TRANSACTION` command provides the recoverable operator path.
HIGH operations remain undispatched until a valid digest-bound approval is
observed after target identity revalidation.

## Alert processing and reports

`serve --once` performs one complete alert poll, processes each accepted
result, persists dedup state and reports, then exits.  The long-running service
uses the same durable poll state.  Runtime results are never discarded.

## Release and CI

Online archives contain the directory expected by the installer.  Release
verification cross-checks `MANIFEST.json`, `SHA256SUMS`, actual files and the
signature before staging.  Windows CI installs build/test dependencies before
running pytest.

## Verification

Each behavior receives a regression test that fails before its production
fix.  Final gates are compileall, the complete pytest suite and source release
verification.  Missing platform dependencies are reported, never treated as
success.
