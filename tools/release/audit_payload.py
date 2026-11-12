#!/usr/bin/env python3
"""Check publication scope and sensitive markers without printing file contents."""

import argparse
import ipaddress
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


MEMBERS = {
    "bin/nodomi-agent",
    "bin/nodomi-agentctl",
    "bin/nodomi-agent-supervisor",
    "services/systemd/nodomi-agent.service",
    "services/openrc/nodomi-agent",
    "LICENSE",
}
SOURCE_ROOT_FILES = {".gitignore", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"}
SOURCE_BUILD_FILES = {"agent/Cargo.toml", "agent/Cargo.lock", "agent/rust-toolchain.toml"}
SOURCE_TEMPLATES = {
    "deploy/agent/systemd/nodomi-agent.service", "deploy/agent/openrc/nodomi-agent",
}
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MARKERS = {
    "development metadata": rb"\bagents?\.md\b|(?:^|[/ ])\.(?:orca|agents|superpowers)(?:/|\s)",
    "development document": rb"docs/(?:deployment|design|research|learning|superpowers)/",
    "project tracker": rb"linear\.app/|\bDAS-[0-9]+\b",
    "repository outside the public release source": rb"DashunLiu/(?!Nodomio\b)[A-Za-z0-9_.-]+",
    "local build path": rb"/(?:Users|home)/[A-Za-z0-9._-]+/|/\x5f\x5fw/|[A-Z]:\\Users\\[^\\\s]+\\",
    "private endpoint": rb"(?:https?|ssh|postgres(?:ql)?|mysql|redis)://[A-Za-z0-9.-]+\.(?:internal|lan|local|home\.arpa)(?=$|[:/\s\x00\"',)\]])",
    "private key": rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    "provider credential": rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9_-]{25,})\b",
}
RULES = {name: re.compile(pattern, re.I) for name, pattern in MARKERS.items()}
URL_AUTHORITY = re.compile(rb"(?:https?|ssh|postgres(?:ql)?|mysql|redis)://[A-Za-z0-9._%+~:\[\]@!$&()*+,;=\-]+", re.I)
EXAMPLE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))


def approved_source(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(part in {".", ".."} for part in parts):
        return False
    if path in SOURCE_ROOT_FILES | SOURCE_BUILD_FILES | SOURCE_TEMPLATES:
        return True
    if path == ".github/workflows/agent-build.yml":
        return True
    suffix = PurePosixPath(path).suffix
    if parts[:2] == ("tools", "release"):
        return len(parts) == 3 and suffix == ".py" and not parts[-1].startswith(".")
    return (
        len(parts) >= 3
        and parts[0] == "agent"
        and parts[1] in {"src", "tests"}
        and suffix in {".rs", ".sql", ".py", ".c", ".txt", ".sh"}
        and all(not part.startswith(".") for part in parts)
        and not any(part.lower() in {"tls", "target"} for part in parts)
    )


def synthetic_userinfo(path: str, data: bytes, url, at: int) -> bool:
    host = url.hostname or ""
    if path in {"agent/src/service_files.rs", "agent/src/installation/plan.rs"}:
        return host.endswith((".example", ".test", ".invalid"))
    start = data.rfind(b"\n", 0, at) + 1
    end = data.find(b"\n", at)
    return (
        path == "agent/tests/fixtures/https_release.py"
        and b"redirect-userinfo" in data[start:end]
        and host in {"release-assets.githubusercontent.com", "objects.githubusercontent.com", "github.com"}
        and url.username in {"user", "fixture", "test", "u"}
        and url.password is None
    )


def audit_bytes(data: bytes, path: str, *, source: bool = False) -> None:
    for name, pattern in RULES.items():
        if pattern.search(data):
            raise ValueError(f"{path}: {name}")
    for hit in URL_AUTHORITY.finditer(data):
        try:
            url = urlsplit(hit.group().decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            continue
        if url.hostname:
            try:
                address = ipaddress.ip_address(url.hostname)
            except ValueError:
                pass
            else:
                if not (address.is_loopback or address.is_unspecified or any(address in net for net in EXAMPLE_NETWORKS)):
                    raise ValueError(f"{path}: literal non-example network address")
        if url.username is None and url.password is None:
            continue
        if source and synthetic_userinfo(path, data, url, hit.start()):
            continue
        raise ValueError(f"{path}: URL with embedded user information")


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def audit_source(root: Path) -> None:
    entries = git(root, "ls-tree", "-rz", "HEAD").split(b"\0")
    seen = set()
    for entry in entries:
        if not entry:
            continue
        meta, name = entry.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        path = name.decode("utf-8")
        if kind != "blob" or mode not in {"100644", "100755"} or not approved_source(path):
            raise ValueError(f"{path}: unexpected source tree entry")
        data = git(root, "cat-file", "blob", oid)
        if b"\0" in data:
            raise ValueError(f"{path}: unexpected binary file")
        data.decode("utf-8")
        audit_bytes(data, path, source=True)
        seen.add(path)
    if not (SOURCE_ROOT_FILES | SOURCE_BUILD_FILES | SOURCE_TEMPLATES).issubset(seen):
        raise ValueError("source tree is missing expected project files")
    print(f"Source scope and privacy checks passed for {len(seen)} committed files")


def audit_archive(path: Path) -> None:
    seen = set()
    total = 0
    with tarfile.open(path, "r|gz") as bundle:
        for entry in bundle:
            total += entry.size
            if entry.name not in MEMBERS or entry.name in seen or not entry.isfile():
                raise ValueError("archive contains an unexpected member")
            if entry.size <= 0 or total > MAX_ARCHIVE_BYTES:
                raise ValueError("archive exceeds the content size budget")
            stream = bundle.extractfile(entry)
            if stream is None:
                raise ValueError("archive member has no readable bytes")
            audit_bytes(stream.read(), entry.name)
            seen.add(entry.name)
    if seen != MEMBERS:
        raise ValueError("archive is missing an expected member")
    print(f"Archive scope and privacy checks passed for {len(seen)} members")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--source", type=Path)
    group.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        if args.source is not None:
            audit_source(args.source)
        else:
            audit_archive(args.archive)
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"Publication audit failed: {error}\n")


if __name__ == "__main__":
    main()
