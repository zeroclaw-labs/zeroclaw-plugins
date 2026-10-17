#!/usr/bin/env python3
"""Tie the shipped bytes to the source tree they were built from.

The rest of this suite argues about the artifacts themselves: what they import,
what they refuse, what they weigh. None of that says where they came from, so a
reader still has to take the link between this commit and those bytes on trust.
This script writes the link down and then checks it, with the standard library,
offline, in about a second on a clean clone.

Four things get recorded, so four things get checked:

  * The vendored core. `libs/solana-core` is the source of truth and each plugin
    carries a copy, because CI snapshots `plugins/<name>` plus `wit/v0` and a
    path dependency reaching outside the plugin cannot resolve there. "One shared
    core" therefore rests on the copies not drifting. Every copied file is
    compared byte for byte against the source. Exactly one file is allowed to
    differ, `Cargo.toml`, because `libs/solana-core/vendor.sh` strips the
    `[workspace]` table on the way in, so that one is checked by applying the
    same edit and demanding an exact match. The tree digest is the algorithm from
    `plugins/*/tests/vendored_core.rs` and has to equal the constant all three of
    those tests pin, which makes a passing run two implementations agreeing on
    one number rather than one implementation trusting itself.

  * The toolchain. There is no `rust-toolchain.toml` here, so nothing overrides
    the compiler for a local build and the authoritative pin is the
    `RUST_TOOLCHAIN` value in `.github/workflows/validate.yml`, which the jobs
    hand to the toolchain action. Both halves are recorded: the value and the
    absence of the file that would outrank it. The artifacts are asked the same
    question separately. A release build with `strip = true` keeps no producers
    entry for rustc, but the panic paths it does keep still spell
    `/rustc/<commit>/`, so the compiler that emitted the bytes is in the bytes.

  * The source. Per plugin, a sha256 for every tracked file the release build or
    the host reads, plus a tree digest over them. Per file, so a failure names the
    file instead of waving at the tree.

  * The artifacts. Size and sha256 for each component, in both places
    `demo/run-demo.sh` leaves them, plus the compiler commit they carry.

What a passing run proves:

  * this working tree is byte for byte the tree the attestation was recorded
    from, for every file the three components compile
  * the three vendored copies of the core are still one core
  * the artifacts on disk are still the exact bytes named in the attestation, in
    both locations, built by the compiler recorded for them

What it does not prove, said plainly because a narrow claim is worth more than an
oversold one:

  * that these sources compiled to those bytes. Nothing here runs a compiler. The
    chain is recorded source, recorded compiler, recorded bytes, all three
    re-derivable at any time. The step that would close it is a rebuild under the
    same rustc. A different rustc gives different bytes, which this script
    diagnoses rather than shrugs at.
  * that the toolchain CI pins is the toolchain that produced these artifacts. It
    is not, so the run says so on every line where it matters. That is a fact
    about the artifacts, not a defect in them. Burying it would be the defect.
  * anything about behaviour. The other verifiers in this directory do that.

The commit id is recorded, not asserted. A commit that touches only documentation
must not turn a byte comparison red, so `recorded_at` prints as a note while
everything under `claims` and `artifacts` fails the run. `--strict` asserts the
head commit too, for a reader who wants the tighter reading.

Usage:

    python3 demo/verify-provenance.py                    # check the pinned attestation
    python3 demo/verify-provenance.py other.json         # check a copy of it
    python3 demo/verify-provenance.py --record           # re-derive and rewrite the pin
    python3 demo/verify-provenance.py --strict           # also assert the head commit

Exit codes: 0 everything matched, 1 something moved, 2 the check could not run
here (no attestation, no git checkout, no built components).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ATTESTATION = HERE / "provenance.expected.json"

PLUGINS = ("nonce-status", "payment-watch", "spl-transfer-build")
CORE = "libs/solana-core"
WORKFLOW = ".github/workflows/validate.yml"
OVERRIDE = "rust-toolchain.toml"
STAGED = "demo/out/staged"
BUILT = "target-shared/wasm32-wasip2/release"

# What libs/solana-core/vendor.sh deliberately leaves behind: the lockfile
# (the plugin's own lock governs the vendored crate) plus the script itself. A
# file joining or leaving this set fails the run instead of passing quietly,
# since either would mean the copies are no longer the source.
NOT_VENDORED = ("Cargo.lock", "vendor.sh")

# The single edit vendor.sh makes on the way in. Cargo refuses two workspace
# roots in one workspace, so the nested crate loses its [workspace] table. This
# is that edit, spelled out here so the exemption cannot cover anything else.
WORKSPACE_TABLE = re.compile(r"\n\[workspace\]\s*\n?")

# Files under a plugin that a release build or the host actually reads. tests/ is
# out because a release cdylib does not compile it. solana-core/ is out because
# the vendored block covers that file by file.
BUILD_INPUTS = ("Cargo.toml", "Cargo.lock", "manifest.toml")

# The constant every plugin carrying the core asserts. This script reproduces it
# from the same files, so the two sides check each other.
PINNED_DIGEST = re.compile(r'VENDORED_CORE_DIGEST: &str =\s*"([0-9a-f]{64})"')


def sha256(data: bytes) -> str:
    """One digest, hex, so every recorded number is produced the same way."""
    return hashlib.sha256(data).hexdigest()


def tree_digest(base: Path, rels: list[str]) -> str:
    """sha256 over files in sorted path order, path and bytes both NUL terminated.

    This is the algorithm in plugins/*/tests/vendored_core.rs, kept identical on
    purpose: the number it produces for a vendored core has to equal the constant
    those tests pin, so the Rust side and this side check each other. NUL after
    each field is what stops a rename colliding with a content change.
    """
    digest = hashlib.sha256()
    for rel in sorted(rels):
        digest.update(rel.encode())
        digest.update(b"\x00")
        digest.update((base / rel).read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def git(*args: str) -> str | None:
    """One git command against the clone. None when git cannot answer."""
    try:
        done = subprocess.run(("git", "-C", str(ROOT)) + args, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout.decode()


def tracked(prefix: str) -> list[str]:
    """Every tracked path under prefix, so a digest covers the committed tree.

    The index is what "tracked" means. It is also what CI builds from, so an
    untracked file cannot quietly become a build input.
    """
    out = git("ls-files", "-z", "--", prefix)
    return sorted(p for p in out.split("\0") if p) if out else []


def toml_head(path: Path) -> dict[str, str]:
    """The top level string keys of a small TOML file, the ones before any table.

    Enough to read a manifest's version and wasm_path without a TOML parser, which
    keeps this script running on any python3 the rig already requires.
    """
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("["):
            break
        match = re.match(r'\s*([A-Za-z_][\w-]*)\s*=\s*"([^"]*)"', line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def workflow_pin(path: Path) -> tuple[str | None, int, int]:
    """The RUST_TOOLCHAIN the workflow declares, plus how many places consume it.

    The standard library has no YAML parser and this directory takes no
    dependencies, so this reads the one key it needs out of the top level env
    block rather than parsing a 400 line workflow.
    """
    text = path.read_text(encoding="utf-8")
    declared = re.search(r'^ {2}RUST_TOOLCHAIN:\s*"?([^\s"]+)', text, re.M)
    installs = re.findall(r"toolchain:\s*\$\{\{\s*env\.RUST_TOOLCHAIN\s*\}\}", text)
    return (declared.group(1) if declared else None), len(installs), text.count("env.RUST_TOOLCHAIN")


def rustc_commits(binary: bytes) -> list[str]:
    """Every rustc commit the bytes name, from the panic paths a release keeps."""
    return sorted({m.decode() for m in re.findall(rb"/rustc/([0-9a-f]{40})/", binary)})


def core_claim() -> tuple[dict, list[str]]:
    """The vendored core: what it is and whether the copies are still it."""
    source = ROOT / CORE
    source_files = [rel[len(CORE) + 1:] for rel in tracked(CORE)]
    hashed = [rel for rel in source_files if rel == "Cargo.toml" or rel.endswith(".rs")]
    expected_copy = sorted(set(source_files) - set(NOT_VENDORED))
    problems: list[str] = []

    # vendor.sh's own edit, reproduced. The vendored Cargo.toml has to be this and
    # nothing else, so "Cargo.toml may differ" cannot become cover for a real change.
    stripped = WORKSPACE_TABLE.sub("\n", (source / "Cargo.toml").read_text(encoding="utf-8"))
    stripped = stripped.rstrip() + "\n"

    copy_digests: set[str] = set()
    test_pins: set[str] = set()
    for plugin in PLUGINS:
        prefix = f"plugins/{plugin}/solana-core"
        base = ROOT / prefix
        rels = [rel[len(prefix) + 1:] for rel in tracked(prefix)]
        if rels != expected_copy:
            extra = sorted(set(rels) - set(expected_copy))
            gone = sorted(set(expected_copy) - set(rels))
            problems.append(
                f"{prefix} is not the file set vendor.sh copies"
                + (f", extra {extra}" if extra else "")
                + (f", missing {gone}" if gone else "")
            )
            continue
        for rel in rels:
            found = (base / rel).read_bytes()
            if rel == "Cargo.toml":
                if found != stripped.encode():
                    problems.append(
                        f"{prefix}/Cargo.toml is not {CORE}/Cargo.toml with the "
                        "[workspace] table removed, which is the only edit vendor.sh makes"
                    )
            elif found != (source / rel).read_bytes():
                problems.append(f"{prefix}/{rel} is not byte-identical to {CORE}/{rel}")
        copy_digests.add(tree_digest(base, [r for r in rels if r in hashed]))
        pin = PINNED_DIGEST.search(
            (ROOT / "plugins" / plugin / "tests" / "vendored_core.rs").read_text(encoding="utf-8")
        )
        test_pins.add(pin.group(1) if pin else f"no constant in plugins/{plugin}/tests/vendored_core.rs")

    if len(copy_digests) > 1:
        problems.append("the vendored copies do not agree with each other: "
                        + ", ".join(sorted(copy_digests)))
    if len(test_pins) > 1:
        problems.append("plugins/*/tests/vendored_core.rs do not pin one digest: "
                        + ", ".join(sorted(test_pins)))
    copy_digest = copy_digests.pop() if len(copy_digests) == 1 else sorted(copy_digests)
    test_pin = test_pins.pop() if len(test_pins) == 1 else sorted(test_pins)
    if copy_digest != test_pin:
        problems.append(f"the vendored core digests {copy_digest} but the Rust tests pin {test_pin}")

    claim = {
        "source_of_truth": CORE,
        "digest_algorithm": "sha256 over sorted relative paths, path and bytes NUL terminated",
        "copies": [f"plugins/{plugin}/solana-core" for plugin in PLUGINS],
        "hashed_files": hashed,
        "left_behind_by_vendor_sh": list(NOT_VENDORED),
        "vendor_script_sha256": sha256((source / "vendor.sh").read_bytes()),
        "source_digest": tree_digest(source, hashed),
        "vendored_digest": copy_digest,
        "pinned_by_the_rust_tests": test_pin,
        "files": {rel: sha256((source / rel).read_bytes()) for rel in source_files},
    }
    return claim, problems


def plugin_claims() -> dict:
    """Per plugin, a digest for every tracked file its release build or host reads."""
    claims = {}
    for plugin in PLUGINS:
        prefix = f"plugins/{plugin}"
        base = ROOT / prefix
        rels = []
        for rel in tracked(prefix):
            inside = rel[len(prefix) + 1:]
            if inside.startswith("solana-core/") or inside.startswith("tests/"):
                continue
            if inside.startswith("src/") or inside in BUILD_INPUTS:
                rels.append(inside)
        manifest = toml_head(base / "manifest.toml")
        claims[plugin] = {
            "version": manifest.get("version"),
            "wasm": manifest.get("wasm_path"),
            "digest": tree_digest(base, rels),
            "files": {rel: sha256((base / rel).read_bytes()) for rel in rels},
        }
    return claims


def wit_claim() -> dict:
    """The WIT the components bind against, which is a build input like any other.

    Each plugin generates its bindings from `path: "../../wit/v0"`, so the world
    the components import is defined here, not in their own source.
    """
    rels = [rel[len("wit") + 1:] for rel in tracked("wit")]
    base = ROOT / "wit"
    upstream = ""
    for line in (base / "UPSTREAM_REF").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            upstream = line.strip()
            break
    return {
        "upstream_ref": upstream,
        "digest": tree_digest(base, rels),
        "files": {rel: sha256((base / rel).read_bytes()) for rel in rels},
    }


def toolchain_claim() -> tuple[dict, list[str], tuple[int, int]]:
    """The compiler this repository pins plus the file that would outrank it."""
    pin, installs, references = workflow_pin(ROOT / WORKFLOW)
    claim = {
        "declared_in": WORKFLOW,
        "rust_toolchain": pin,
        "rust_toolchain_toml_present": (ROOT / OVERRIDE).is_file(),
    }
    problems = []
    if pin is None:
        problems.append(f"{WORKFLOW} declares no RUST_TOOLCHAIN, so nothing here pins the compiler")
    return claim, problems, (installs, references)


def artifact_claims(plugins: dict) -> tuple[dict, list[str]]:
    """Size, digest and compiler for each staged component, plus what is not built."""
    claims = {}
    absent = []
    for plugin, info in plugins.items():
        if not info["wasm"]:
            absent.append(f"plugins/{plugin}/manifest.toml declares no wasm_path")
            continue
        staged = ROOT / STAGED / plugin / info["wasm"]
        if not staged.is_file():
            absent.append(f"{STAGED}/{plugin}/{info['wasm']}")
            continue
        blob = staged.read_bytes()
        claims[plugin] = {
            "wasm": info["wasm"],
            "bytes": len(blob),
            "sha256": sha256(blob),
            "rustc_commits": rustc_commits(blob),
        }
    return claims, absent


def artifact_side_checks(plugins: dict) -> tuple[list[str], list[str]]:
    """The two claims about a staged artifact that need no pinned copy to check.

    The bytes cargo emitted and the bytes the demo publishes have to be one set of
    bytes. The descriptor beside a component has to be the tracked one. Otherwise
    the manifest a host reads is not the manifest this repository reviewed.
    """
    problems: list[str] = []
    notes: list[str] = []
    for plugin, info in plugins.items():
        name = info["wasm"]
        if not name:
            continue
        staged = ROOT / STAGED / plugin / name
        if not staged.is_file():
            continue
        blob = staged.read_bytes()
        built = ROOT / BUILT / name
        if not built.is_file():
            notes.append(f"{name}: nothing under {BUILT}, which is where run-demo.sh builds")
        elif built.read_bytes() != blob:
            problems.append(f"{BUILT}/{name} and {STAGED}/{plugin}/{name} are different bytes")
        else:
            notes.append(f"{name}: the staged copy and the {BUILT} copy are the same bytes")
        descriptor = staged.parent / "manifest.toml"
        tracked_descriptor = ROOT / "plugins" / plugin / "manifest.toml"
        if not descriptor.is_file():
            problems.append(f"{STAGED}/{plugin}/manifest.toml is missing, so it ships undescribed")
        elif descriptor.read_bytes() != tracked_descriptor.read_bytes():
            problems.append(f"{STAGED}/{plugin}/manifest.toml is not the tracked copy")
    return problems, notes


def rustc_here() -> str:
    """The local compiler, for the record only.

    Never asserted. A reader on a different machine has a different rustc and that
    is fine: the compiler claim that matters is the commit inside the artifacts.
    """
    try:
        done = subprocess.run(("rustc", "--version"), capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return "not on this machine"
    return done.stdout.decode().strip()


def derive() -> dict:
    """Everything this script knows about the tree in front of it, in one dict."""
    core, core_problems = core_claim()
    toolchain, toolchain_problems, usage = toolchain_claim()
    plugins = plugin_claims()
    artifacts, absent = artifact_claims(plugins)
    side_problems, notes = artifact_side_checks(plugins)
    head = git("rev-parse", "HEAD") or ""
    branch = git("rev-parse", "--abbrev-ref", "HEAD") or ""
    pinned_paths = [CORE, "wit", WORKFLOW] + [f"plugins/{p}" for p in PLUGINS]
    touched = git("log", "-1", "--format=%H", "--", *pinned_paths) or ""
    return {
        "attestation": {
            "schema": "zeroclaw-solana-provenance/1",
            "recorded_at": {
                "utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "head_commit": head.strip(),
                "branch": branch.strip(),
                "last_commit_touching_the_pinned_paths": touched.strip(),
                "rustc_on_the_recording_machine": rustc_here(),
            },
            "claims": {
                "toolchain": toolchain,
                "core": core,
                "wit": wit_claim(),
                "plugins": plugins,
            },
            "artifacts": artifacts,
        },
        "problems": core_problems + toolchain_problems + side_problems,
        "absent": absent,
        "notes": notes,
        "toolchain_usage": usage,
    }


def brief(value: object) -> str:
    """A value short enough to read in a failure line."""
    text = json.dumps(value) if not isinstance(value, str) else value
    return text if len(text) <= 72 else text[:69] + "..."


def differences(pinned: object, found: object, where: str = "") -> list[str]:
    """Every field where the pinned copy and this tree disagree, named by path."""
    problems: list[str] = []
    if isinstance(pinned, dict) and isinstance(found, dict):
        for key in sorted(set(pinned) | set(found)):
            child = f"{where}.{key}" if where else key
            if key not in pinned:
                problems.append(f"{child}: not in the attestation, this tree has {brief(found[key])}")
            elif key not in found:
                problems.append(f"{child}: pinned as {brief(pinned[key])}, gone from this tree")
            else:
                problems.extend(differences(pinned[key], found[key], child))
    elif pinned != found:
        problems.append(f"{where}: pinned {brief(pinned)}, this tree has {brief(found)}")
    return problems


def compiler_note(pinned: dict, found: dict) -> list[str]:
    """Say when a digest moved because the compiler moved, rather than leave a riddle."""
    notes = []
    for plugin in sorted(set(pinned) & set(found)):
        was = pinned[plugin].get("rustc_commits")
        now = found[plugin].get("rustc_commits")
        if pinned[plugin].get("sha256") != found[plugin].get("sha256") and was != now:
            notes.append(
                f"{plugin}: the compiler moved too, pinned {brief(was)} against {brief(now)}. "
                "Different rustc, different bytes. Rebuild under the pinned one or re-record."
            )
    return notes


def toolchain_lines(claim: dict, usage: tuple[int, int], local: str, commits: list[str]) -> list[str]:
    """The compiler story: what the repo pins, what the bytes carry, whether they agree."""
    pin = claim["rust_toolchain"]
    installs, references = usage
    lines = [
        f"{claim['declared_in']} pins RUST_TOOLCHAIN {pin}, {installs} jobs install it,"
        f" {references} references in all",
        f"no {OVERRIDE} in the tree, so nothing overrides that pin for a local build"
        if not claim["rust_toolchain_toml_present"]
        else f"{OVERRIDE} is present, so it outranks the workflow pin for a local build",
    ]
    if not commits:
        lines.append("the artifacts name no compiler, so this run cannot say what built them")
        return lines
    lines.append("the artifacts carry rustc commit " + ", ".join(commits))
    release = local.split()[1] if local.startswith("rustc ") else ""
    short = re.search(r"\(([0-9a-f]{7,40}) ", local)
    built_here = bool(short) and any(c.startswith(short.group(1)) for c in commits)
    lines.append(f"rustc on this machine: {local}")
    if built_here and release == pin:
        lines.append(f"that is the pinned {pin}, so these bytes and CI's bytes come from one compiler")
    elif built_here:
        lines.append(
            f"NOTE that is {release}, not the pinned {pin}. These digests are from {release}."
            f" A build under {pin} produces different bytes, which is expected, not a defect"
        )
    else:
        lines.append(
            "NOTE the compiler in the bytes is not the rustc on this machine, so this run"
            " cannot name its version. Only its commit is provable from here"
        )
    return lines


def shown(path: Path) -> str:
    """A path a reader can retype, relative to the clone when it is inside it."""
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def show(state: dict, pinned: dict, path: Path) -> None:
    """The chain in the order it runs: where it was pinned, the core, the compiler,
    the source, the bytes."""
    found = state["attestation"]
    here = found["recorded_at"]
    there = pinned.get("recorded_at", here)
    core = found["claims"]["core"]
    plugins = found["claims"]["plugins"]
    wit = found["claims"]["wit"]

    print("provenance for the solana payment suite, three components")
    print(f"  attestation  {shown(path)}, recorded {there.get('utc')}"
          f" at {there.get('head_commit', '')[:7]}")
    print(f"  this tree    {here['head_commit'][:7]} on {here['branch']}, "
          f"pinned paths last moved at {here['last_commit_touching_the_pinned_paths'][:7]}")

    copies = len(core["copies"])
    print("\nvendored core")
    print(f"  {CORE}: {len(core['files'])} tracked files, "
          f"{len(core['files']) - len(NOT_VENDORED)} copied into each of {copies} plugins, "
          f"{len(NOT_VENDORED)} left behind ({', '.join(NOT_VENDORED)})")
    print("  every copied file byte-identical, Cargo.toml identical after vendor.sh's [workspace] strip")
    print(f"  vendored digest {core['vendored_digest']}")
    print(f"  the same constant plugins/*/tests/vendored_core.rs pins:"
          f" {core['pinned_by_the_rust_tests']}")
    print(f"  source digest   {core['source_digest']}, which differs by that one table alone")

    print("\ntoolchain")
    commits = sorted({c for a in found["artifacts"].values() for c in a["rustc_commits"]})
    for line in toolchain_lines(found["claims"]["toolchain"], state["toolchain_usage"],
                                here["rustc_on_the_recording_machine"], commits):
        print(f"  {line}")

    print("\nsource, tracked files only, digested per file")
    for plugin in PLUGINS:
        claim = plugins[plugin]
        print(f"  {plugin:<20} {claim['version']:<7} {len(claim['files']):>2} files  {claim['digest']}")
    print(f"  {'wit, the bound world':<20} {'':<7} {len(wit['files']):>2} files  {wit['digest']}")
    print(f"  wit/v0 tracks zeroclaw-labs/zeroclaw at {wit['upstream_ref']}")

    print("\nartifacts")
    for plugin in PLUGINS:
        artifact = found["artifacts"].get(plugin)
        if artifact is None:
            print(f"  {plugin}: not built here")
            continue
        print(f"  {artifact['wasm']:<24} {artifact['bytes']:>7} bytes  sha256 {artifact['sha256']}")
    for note in state["notes"]:
        print(f"  {note}")


def comparable(document: dict, with_artifacts: bool) -> dict:
    """The part of an attestation that is asserted rather than recorded."""
    subset = {"schema": document.get("schema"), "claims": document.get("claims", {})}
    if with_artifacts:
        subset["artifacts"] = document.get("artifacts", {})
    return subset


def main(argv: list[str]) -> int:
    record = "--record" in argv
    strict = "--strict" in argv
    rest = [a for a in argv if not a.startswith("--")]
    if len(rest) > 1 or set(argv) - set(rest) - {"--record", "--strict"}:
        print("usage: verify-provenance.py [attestation.json] [--record] [--strict]")
        return 2
    toplevel = (git("rev-parse", "--show-toplevel") or "").strip()
    if not toplevel:
        print(f"{ROOT} is not a git checkout, so the tracked file list cannot be read here")
        return 2
    if Path(toplevel).resolve() != ROOT:
        print(f"this script expects the clone root at {ROOT}, git reports {toplevel}")
        return 2

    path = Path(rest[0]) if rest else ATTESTATION
    state = derive()
    found = state["attestation"]

    if record:
        if state["absent"]:
            print("the components are not built here, so there is nothing to pin:")
            for missing in state["absent"]:
                print(f"  {missing}")
            print("  build them first with demo/run-demo.sh")
            return 2
        path.write_text(json.dumps(found, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        show(state, found, path)
        digests = len(found["claims"]["core"]["files"]) + len(found["claims"]["wit"]["files"]) + sum(
            len(p["files"]) for p in found["claims"]["plugins"].values())
        print()
        for problem in state["problems"]:
            print(f"  FAIL {problem}")
        if state["problems"]:
            print(f"\nFAIL this tree does not hold together, {len(state['problems'])} problem(s) above.")
            print("  Nothing was pinned that fixes them, so read them before trusting the file.")
            return 1
        print(f"RECORDED {shown(path)} at {found['recorded_at']['head_commit'][:7]}, "
              f"{digests} file digests and {len(found['artifacts'])} artifacts.")
        print("  check it with: python3 demo/verify-provenance.py")
        return 0

    if not path.is_file():
        print(f"no attestation at {shown(path)}. Record one with:"
              " python3 demo/verify-provenance.py --record")
        return 2
    pinned = json.loads(path.read_text(encoding="utf-8"))

    checkable = not state["absent"]
    moved = differences(comparable(pinned, checkable), comparable(found, checkable))
    if strict:
        for key in ("head_commit", "last_commit_touching_the_pinned_paths"):
            was = pinned.get("recorded_at", {}).get(key)
            now = found["recorded_at"][key]
            if was != now:
                moved.append(f"recorded_at.{key}: pinned {brief(was)}, this tree has {brief(now)}")
    problems = state["problems"] + moved
    show(state, pinned, path)

    head = found["recorded_at"]["head_commit"][:7]
    was_head = pinned.get("recorded_at", {}).get("head_commit")
    if not strict and was_head != found["recorded_at"]["head_commit"]:
        print("\n  NOTE the head commit moved since this was recorded. Commit ids are recorded,"
              " not asserted, so the digests above are what decide the verdict. --strict asserts them")

    print()
    for problem in problems:
        print(f"  FAIL {problem}")
    for note in compiler_note(pinned.get("artifacts", {}), found["artifacts"]):
        print(f"  {note}")
    if problems:
        print(f"\nFAIL provenance drifted at {head}, {len(problems)} field(s) moved, listed above.")
        print("  If the change is meant, re-pin with --record and say so in the PR. If it is not,")
        print("  this tree is not the tree those artifacts came from.")
        return 1
    if not checkable:
        print("the source chain matches the attestation, the bytes could not be checked here:")
        for missing in state["absent"]:
            print(f"  no {missing}")
        print("  build them with demo/run-demo.sh, then this run checks the artifacts too.")
        return 2

    claims = found["claims"]
    digests = len(claims["core"]["files"]) + len(claims["wit"]["files"]) + sum(
        len(p["files"]) for p in claims["plugins"].values())
    commits = sorted({c for a in found["artifacts"].values() for c in a["rustc_commits"]})
    print(f"PASS provenance holds at {head}, re-derived from this tree.")
    print(f"  {len(found['artifacts'])} artifacts matched by size and sha256, in both locations")
    print(f"  {len(claims['core']['copies'])} vendored copies of {CORE}, identical to it and to the"
          f" digest the Rust tests pin")
    print(f"  {digests} tracked file digests re-derived, every one as pinned")
    print(f"  compiler: repo pins {claims['toolchain']['rust_toolchain']}, the bytes carry rustc "
          + (commits[0][:12] if commits else "no commit at all"))
    print("  anyone can re-derive it: python3 demo/verify-provenance.py")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
