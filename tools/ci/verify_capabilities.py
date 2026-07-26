#!/usr/bin/env python3
"""Prove each shipped component can only do what its manifest declares.

Every other check in this repository reads the *source*. This one reads the
compiled `.wasm` that an operator actually installs, and asks what capabilities
it imports from the host.

That matters because the security claims are about the artifact, not the
repository. "The plugin holds no keys and stores nothing" is a statement about
a binary somebody downloads. Source can be audited and then something else
shipped; a component's import list cannot lie about what it is able to call.

Fails if a component imports a capability outside its declared permissions —
most importantly `wasi:filesystem` (persistence) or `wasi:sockets` (raw
network). A component that cannot import them cannot use them, whatever its
code says.

Usage:  python tools/ci/verify_capabilities.py [staged_dir]
Requires `wasm-tools` on PATH.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Host capability -> the manifest permission that authorises it.
PERMISSION_FOR_IMPORT = {
    "wasi:http": "http_client",
    "wasi:sockets": None,  # never legitimate for a Safe Hands plugin
    "wasi:filesystem": None,  # never legitimate: components must be stateless
}

# Imports the wasm32-wasip2 target links in for any Rust binary: stdio, exit,
# clocks, the io plumbing wasi:http itself is built on. They grant no ambient
# authority the host does not already mediate, and no plugin can avoid them.
RUNTIME_PLUMBING = (
    "wasi:cli/",
    "wasi:clocks/",
    "wasi:io/",
    "wasi:random/",
    "zeroclaw:plugin/",
)

# Capabilities whose mere presence is a finding, regardless of manifest.
FORBIDDEN = ("wasi:filesystem", "wasi:sockets")


def component_imports(wasm: Path) -> set[str]:
    """Interface names the component imports, e.g. {'wasi:http/types'}."""
    try:
        wit = subprocess.run(
            ["wasm-tools", "component", "wit", str(wasm)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except FileNotFoundError:
        sys.exit("error: wasm-tools is not on PATH — cargo install wasm-tools")
    except subprocess.CalledProcessError as error:
        sys.exit(f"error: {wasm.name} is not a valid component: {error.stderr.strip()}")

    imports = set()
    for line in wit.splitlines():
        match = re.match(r"\s+import\s+([^;@]+)", line)
        if match:
            imports.add(match.group(1).strip())
    return imports


def declared_permissions(manifest: Path) -> set[str]:
    text = manifest.read_text(encoding="utf-8")
    # Only the real assignment line, not prose in a comment above it.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("permissions") and "=" in stripped:
            return set(re.findall(r'"([a-z_]+)"', stripped))
    return set()


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    staged = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "dist" / "local"
    if not staged.is_dir():
        sys.exit(f"error: {staged} not found — run `just stage-local` first")

    failures: list[str] = []
    checked = 0

    for plugin_dir in sorted(p for p in staged.iterdir() if p.is_dir()):
        wasms = list(plugin_dir.glob("*.wasm"))
        manifest = plugin_dir / "manifest.toml"
        if not wasms or not manifest.is_file():
            continue

        name = plugin_dir.name
        permissions = declared_permissions(manifest)
        imports = component_imports(wasms[0])
        checked += 1

        undeclared = []
        for interface in sorted(imports):
            if interface.startswith(RUNTIME_PLUMBING):
                continue
            namespace = interface.split("/", 1)[0]

            if any(interface.startswith(bad) for bad in FORBIDDEN):
                undeclared.append(f"{interface} (forbidden: never legitimate here)")
                continue

            required = PERMISSION_FOR_IMPORT.get(namespace, "UNMAPPED")
            if required == "UNMAPPED":
                undeclared.append(f"{interface} (unrecognised capability)")
            elif required not in permissions:
                undeclared.append(f"{interface} (needs '{required}', not declared)")

        if undeclared:
            failures.append(f"{name}: " + "; ".join(undeclared))
            print(f"  FAIL  {name}")
            for item in undeclared:
                print(f"        {item}")
        else:
            granted = ", ".join(sorted(permissions)) or "none"
            print(f"  ok    {name:<24} declares [{granted}], imports nothing beyond them")

    if not checked:
        sys.exit(f"error: no staged components found under {staged}")

    if failures:
        print(f"\n{len(failures)} component(s) import undeclared capabilities.")
        return 1

    print(
        f"\nAll {checked} components verified: no filesystem, no sockets, "
        "nothing beyond declared permissions."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
