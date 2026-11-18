# Plugin registry CI

This repository uses a deterministic validation and publication pipeline for
its standalone WebAssembly plugin crates. It checks source, metadata, WIT,
component builds, and immutable packages. It does not run an LLM or post an
automated review comment.

The workflow files are authoritative for executable behavior. This document
records their operator-facing contracts and the conditions for expanding the
pipeline.

## Required check contract

`Validate Required Gate` is the only status check that the `main` ruleset
requires. The display name is a frozen external contract: internal jobs may be
added, removed, or reorganized without changing it. A planned rename must be
coordinated with the ruleset so pull requests are never left waiting forever
for a check name that no workflow emits.

After rollout, the ruleset must use strict required-status behavior so an
immutability-sensitive pull request is revalidated against the current `main`.
The GitHub Actions integration is not a ruleset bypass actor. A generated
registry commit receives the same integration-owned gate context before its
fast-forward push, as described under Publication. The administrator bypass is
break-glass recovery, not the normal merge path. Review requirements remain
deferred as described under Phase B.

Validation runs for every pull request without a path filter. This is
load-bearing: GitHub leaves a path-filtered required check in an `Expected`
state on a non-matching pull request. Documentation-only changes therefore
still receive the gate, while component and packaging work can be skipped.

## Validation pipeline

`.github/workflows/validate.yml` runs on `pull_request`, manual dispatch, and
as the reusable workflow called by publication. Pull-request jobs have only
`contents: read` permission and receive no secrets.

The job flow is:

```text
fmt
├─▶ changes ─▶ components (shards) ─▶ package ─┐
├─▶ registry ──────────────────────────────────┤
└─▶ wit-drift ─────────────────────────────────┴─▶ gate
```

- `fmt` inspects every plugin and rejects whitespace errors in the
  pull-request diff. New or changed Rust sources must be clean. Untouched
  baseline formatting debt emits a warning derived from the merge-base, not a
  maintained exception list. A plugin becomes strict automatically when it is
  version-bumped and formatted; formatting an already published same-version
  component is not allowed because it can change immutable WASM bytes.
- `changes` selects changed plugins on pull requests. A change under `wit/`,
  `tools/`, `.github/`, or to `registry.json` forces a full sweep. Non-PR
  events also run a full sweep. A documentation-only pull request can produce
  an empty matrix.
- `registry` verifies that every plugin has the required crate and manifest
  files, runs the registry-builder unit tests, requires source changes to leave
  the generated `registry.json` release identities and history against the
  base, allows only manifest-derived metadata refreshes, and checks generated
  metadata against canonical `manifest.toml` data. The host-gated `state_read`
  and `state_write` permissions are accepted only in a `registry = false`
  plugin, because released hosts reject a manifest that requests them.
- `wit-drift` fetches and cryptographically verifies the ZeroClaw Git object at
  the revision in `wit/UPSTREAM_REF`, then
  requires its `wit/v0` directory to be byte-identical to this repository's
  vendored directory. Advance the pin and vendored WIT together in one
  reviewed change; never point the pin at a merely compatible or partially
  matching tree. When `wit/next` exists, the same check compares it with
  ZeroClaw's `wit/v0` at `wit/NEXT_REF`, an unreleased host revision; the pin
  and the directory must be added and removed together.
  A `wit/current` / `wit/CURRENT_REF` pair, when present, receives the same byte-equality check. None exists while `wit/v0` is the newest host contract.
- `components` uses bounded shards and validates every selected plugin with
  locked host tests, host Clippy, `wasm32-wasip2` Clippy, and a release WASM
  build. Tests and builds are always strict. A plugin changed by the current
  source delta is also strict for both Clippy targets; untouched, pre-existing
  Clippy debt remains visible as a warning derived from the delta rather than a
  stored exception list. This is necessary because repairing a published
  same-version component would violate its immutable package digest. Plugins
  marked `registry = false` receive the same validation and are staged as
  run-internal evidence, but the registry builder omits them from release
  packages. Each plugin builds from a snapshot of the committed `wit/` tree;
  only a `registry = false` plugin's snapshot includes `wit/next`, so a plugin
  headed for the registry cannot bind the unreleased contract.
  When a `wit/current` directory exists, the shared current-contract consumer policy decides which registry-enabled guests retain it; every other registry-enabled guest has that directory withheld. Source-only guests retain their staging access.
- `package` merges the staged shard artifacts and performs a dry-run registry
  build. The staged directory identities must exactly match the existing shard
  matrix before packaging; missing, substituted, or unexpected components fail
  closed. An unchanged historical identity reuses its immutable ledger entry
  instead of assuming a newer compiler can reproduce old WASM. A plugin marked
  as a changed release input by that same matrix may not reuse an existing
  `<name>@<version>`; its canonical manifest version must advance. A `wit/v0`
  change marks every selected plugin as a release input, so a coordinated
  ABI update cannot silently leave old packages behind. A `wit/next` change
  forces a full validation sweep but marks no release inputs, because only
  `registry = false` plugins bind it. The resulting
  `registry-dry-run` artifact is both available for maintainer inspection and
  the sole input to publication; publication never creates a second archive
  from the staged bytes. Generation requires a fresh output directory, and an
  exact-set check rejects any file or digest not derived from newly added
  ledger identities.

A change under `wit/current/`, to `wit/CURRENT_REF`, or to its shared policy in `tools/registry_contract.py` also forces full validation and selects only the current-contract consumers as release inputs, unioned with directly changed plugins. The planner and snapshot validator use that same consumer policy. Adopting a current contract for another registry guest requires an explicit policy change; it cannot silently reuse an existing package identity. This does not alter the v0 fanout rule or relax the next-contract exclusion.
- The gate always runs, aggregates shard results into the GitHub step summary,
  and requires report identities and strictness to match that same shard matrix
  exactly. It fails if any required dependency failed or was cancelled.
  Legitimately skipped component work, such as a documentation-only change, is
  a pass.

The summary identifies the validated commit, selection mode, and plugin count,
then reports tests, host and WASM Clippy, build status, and artifact size for
each component. Artifact size is shown against the host cap, with a soft
warning for unusually large components.

## Reproducibility and cache policy

The Rust toolchain and `wasm32-wasip2` target are pinned by the workflow rather
than following `stable`. GitHub Actions are pinned by full commit SHA; their
source of truth mirrors the corresponding actions in the
`zeroclaw-labs/zeroclaw` workflows. Registry archives are generated and tested
inside the immutable Python image named by `tools/ci/packager-image.txt`, with
network access disabled and an explicit DEFLATE level. A golden archive digest
detects changes in the complete serialization and compression path.

Plugin crates are independent workspaces with independent lockfiles. Component
jobs therefore use an explicit shared Cargo target directory and manual cache
restore/save steps instead of assuming a single root workspace. Pull requests
may restore caches, but only trusted `main` validation writes them.

## Publication

`.github/workflows/publish.yml` is the single pipeline for every push to `main`
and has no path filter. Publication has no branch-selectable manual trigger:
otherwise a branch could change its own workflow guard and request write
permissions outside the trusted `main` path. Main-push runs are serialized
without cancelling an active run. GitHub coalesces pending runs to the newest
main revision; an active run also exits cleanly before publication if it has
already been superseded.

The first job calls the reusable validation workflow, which performs a full
sweep of the merged commit. Publication downloads the `registry-dry-run` from
that same run and uploads those exact package bytes; it neither rebuilds
components nor repackages their output. The release base derives from
`GITHUB_REPOSITORY`, so testing in a fork targets only that fork's release.

Release assets use immutable `<name>-<version>.zip` identities. Uploads never
clobber an existing asset: a retry skips an existing asset only after proving
its bytes are identical, and every URL and digest in the complete generated
ledger is checked before a registry commit. The registry builder refuses
changed bytes for an existing identity. After upload, the workflow pushes the
refreshed `registry.json` only when `main` still equals the validated source
revision. It retries transient push failures but never rebases generated bytes
across newer source.

The required check applies to the generated child commit as well as ordinary
pull requests. Before updating `main`, publication proves that the child has
the validated source as its parent and changes only `registry.json`, uploads
that exact commit to a run-scoped temporary branch, and uses the run-scoped
GitHub Actions token to attach a successful `Validate Required Gate` check.
Only then does it fast-forward the same commit to `main`; the temporary ref is
removed on exit with a SHA-bound lease. Cleanup is best-effort if the runner is
terminated, so a stale `registry-publication/*` branch may be deleted after
confirming that it is not used by an active publication run. A workflow-token
push does not recursively start a run.

### Retiring a published version

`registry-retirements.json` is the reviewed ledger of published
`<name>@<version>` identities withdrawn from the index, for example versions
that no supported host can load. Each entry names the identity, the `sha256`
of its published archive and a reason. Entries are kept in canonical
name/version order.

The ledger is append-only, and the history check enforces it: validation
compares it with the base revision's ledger (an empty one when the base
predates it). An entry may not be removed, and its name, version and `sha256`
may not change; only its `reason` may be reworded. Every entry a change adds
must name a version the base `registry.json` indexes, with that version's
published `sha256`, so a typo or a never-published identity fails. A listed
identity therefore stays reserved.

Every registry builder call in validation and publication passes the ledger,
and the builder refuses to run against a `registry.json` that has the ledger
beside it unless the ledger is passed. The packaging dry run drops each listed
entry from the generated `registry.json` when the entry's `sha256` matches, and
fails if it does not. `--check-history` and `--check-publication` accept the
removal of exactly the listed entries; any other removal still fails. A listed
identity can never be indexed again: packaging refuses a staged plugin at that
version, and `--check-metadata` and `--check-history` refuse a
registry-enabled source manifest at that version. A `registry = false` source
at a listed version is allowed and is never packaged.

A ledger change merges like any source change, but only publication rewrites
`registry.json`. Until the next publication run, the checked-in index may still
hold a listed entry. `--check-history` reports it as a warning, which validation
surfaces as an annotation because a publication run is due; the publication
candidate must not contain it, so `--check-publication` fails if it does.
Because the history check accepts a listed entry's removal, a change that
deletes such an entry from `registry.json` by hand is tolerated: the result is
exactly what publication produces. Any other hand edit fails, except a
canonical metadata refresh from `--sync-metadata`. Changing the ledger forces
full validation, so the dry run exercises it.

Retirement removes index entries, never release assets. Hosts stop being
offered a retired version; its asset URL and bytes stay unchanged on the
`plugins` release.

## Fork security boundary

A fork pull request can modify its copy of the validation workflow and may be
able to make an altered job report the frozen gate name. This is a residual
risk while CODEOWNERS and mandatory reviews are intentionally deferred.

The current mitigations limit impact rather than pretending the risk is gone:

- pull-request validation is read-only and receives no repository secrets;
- publication is unreachable from pull-request context;
- a workflow or tooling change forces full component validation;
- publication independently validates the merged `main` commit before writing
  releases or the registry; and
- reviewers must scrutinize changes under `.github/workflows/` and `tools/`.

Do not replace this with `pull_request_target` plus execution of untrusted
pull-request code; that would cross the repository's trust boundary.

## Phase B graduation triggers

The following work is deliberately deferred until its trigger is true.

| Item | Trigger to build |
| --- | --- |
| Real-host compatibility job | The host runtime surface, including WebSocket and raw-socket behavior, is stable; the compatibility harness has moved out of `.context`; and instantiating every registry component with the `plugins-wasm-cranelift` host, including identity, webhook, and health checks, fits within 10 minutes. |
| Ed25519 signing during publication | Host-side signature verification ships in `zeroclaw plugin install`; signing then uses a protected publication environment and an authorized key. |
| WIT breaking-change automation | Upstream `wit/v0/.frozen` exists. Until then, byte equality against `wit/UPSTREAM_REF` is the stricter invariant. |
| Nightly dependency audit | The initial validation and publication pipeline has proven stable; add a full sweep, per-lockfile audit, and deduplicated issue filing. |
| CODEOWNERS and required reviews | A second active maintainer is available to satisfy and administer the review rule. |

## Rollback and recovery

- If validation logic regresses, revert the offending pipeline change while
  preserving the frozen gate name. Use the administrator ruleset bypass only
  as a documented break-glass action, then restore a working gate immediately.
- If a WIT update is wrong, revert `wit/v0` and `wit/UPSTREAM_REF` (or
  `wit/next` and `wit/NEXT_REF`) as a pair to the last byte-identical
  revision. Do not weaken the drift comparison.
- Before publication, a plugin change can be reverted normally. After an asset
  is published, never delete, overwrite, or reuse its version. Keep historical
  assets intact, revert host selection to a compatible pinned version, and
  publish corrected bytes under a new version. Withdraw a broken version from
  the index through `registry-retirements.json`; validation rejects any other
  removal from `registry.json`.
- If upload succeeds but the registry push races with newer source, let the
  newest main run reconcile it when that source still contains the version. If
  newer source reverted the version, its uploaded asset remains permanently
  reserved: restoring that version must reproduce the identical bytes, while a
  different fix must use a new version. The retry verifies and reuses identical
  assets; a same-name byte mismatch remains a hard failure. Never use clobbering
  upload flags or hand-edit the generated ledger.
- If a publication workflow itself is faulty, disable or revert that workflow
  before retrying. Validation artifacts are evidence, not authorization to
  mutate an existing release identity.
