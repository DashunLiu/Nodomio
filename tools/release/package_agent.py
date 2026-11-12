"""Build and independently verify the canonical Linux Agent package."""

import argparse
import contextlib
import dataclasses
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import tempfile
from typing import BinaryIO
import zlib

ELF_MACHINES = {"linux-x86_64": 62, "linux-aarch64": 183}
CHUNK = 64 * 1024
MAX_CONTENT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_SERVICE_BYTES = 64 * 1024
MAX_LICENSE_BYTES = 1024 * 1024
GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
MEMBERS = (
    ("bin/nodomi-agent", 0o755),
    ("bin/nodomi-agentctl", 0o755),
    ("bin/nodomi-agent-supervisor", 0o755),
    ("services/systemd/nodomi-agent.service", 0o644),
    ("services/openrc/nodomi-agent", 0o755),
    ("LICENSE", 0o644),
)
# Dynamic tags that request a shared library, a search path, or loader auditing.
LOADER_TAGS = {1, 15, 29, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF}


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


@contextlib.contextmanager
def open_regular(path, minimum, maximum):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or not minimum <= before.st_size <= maximum:
            raise ValueError(f"invalid regular file size: {path.name}")
        yield source, before.st_size
        if file_identity(os.fstat(source.fileno())) != file_identity(before):
            raise ValueError(f"file changed during inspection: {path.name}")


def check_static_elf(source, size, platform, member):
    def reject():
        raise ValueError(f"expected a static {platform} ELF executable: {member}")

    prefix = source.read(min(size, CHUNK))
    if (len(prefix) < 64 or prefix[:7] != b"\x7fELF\x02\x01\x01"
            or prefix[7] not in (0, 3)):
        reject()
    kind, machine, version = struct.unpack_from("<HHI", prefix, 16)
    entry, table = struct.unpack_from("<QQ", prefix, 24)
    header_size, row_size, count = struct.unpack_from("<HHH", prefix, 52)
    if (kind not in (2, 3) or machine != ELF_MACHINES[platform] or version != 1
            or header_size != 64 or row_size != 56 or not count
            or table < 64 or table + count * 56 > len(prefix)):
        reject()

    entry_backed = False
    dynamic = None
    for index in range(count):
        segment = struct.unpack_from("<IIQQQQQQ", prefix, table + index * 56)
        segment_type, flags, offset, address, _, length, memory, alignment = segment
        if segment_type != 0 and length and offset + length > size:
            reject()
        if segment_type == 1:  # PT_LOAD
            if (length > memory or address + memory >= 1 << 64
                    or (alignment > 1 and (alignment & (alignment - 1)
                                          or offset % alignment != address % alignment))):
                reject()
            entry_backed |= bool(flags & 1 and address <= entry < address + length)
        elif segment_type == 3:  # PT_INTERP
            reject()
        elif segment_type == 2:  # PT_DYNAMIC, allowed for static PIE
            if dynamic is not None or not 16 <= length <= CHUNK or length % 16:
                reject()
            dynamic = (offset, length)

    if not entry or not entry_backed:
        reject()
    if dynamic is not None:
        offset, length = dynamic
        source.seek(offset)
        tags = struct.iter_unpack("<qQ", source.read(length))
        for tag, _ in tags:
            if tag in LOADER_TAGS:
                reject()
            if tag == 0:
                break
        else:
            reject()


@dataclasses.dataclass(frozen=True)
class Member:
    path: str
    mode: int
    length: int
    sha256: str
    snapshot: BinaryIO

    def tarinfo(self):
        entry = tarfile.TarInfo(self.path)
        entry.size = self.length
        entry.mode = self.mode
        return entry

    def evidence(self):
        return {"path": self.path, "mode": f"{self.mode:04o}",
                "length": self.length, "sha256": self.sha256}


def snapshot_members(root, bins, license_path, platform, stack):
    remaining = MAX_CONTENT_BYTES
    members = []
    for name, mode in MEMBERS:
        binary = name.startswith("bin/")
        if binary:
            path = bins / name.removeprefix("bin/")
            maximum = MAX_CONTENT_BYTES
        elif name == "LICENSE":
            path = license_path
            maximum = MAX_LICENSE_BYTES
        else:
            path = root / "deploy/agent" / name.removeprefix("services/")
            maximum = MAX_SERVICE_BYTES
        snapshot = stack.enter_context(tempfile.TemporaryFile("w+b"))
        digest = hashlib.sha256()
        with open_regular(path, 64 if binary else 1, min(remaining, maximum)) as (source, size):
            todo = size
            while todo:
                chunk = source.read(min(todo, CHUNK))
                if not chunk:
                    raise ValueError(f"truncated input: {name}")
                snapshot.write(chunk)
                digest.update(chunk)
                todo -= len(chunk)
        snapshot.seek(0)
        if binary:
            check_static_elf(snapshot, size, platform, name)
        else:
            text = snapshot.read()
            if b"\0" in text:
                raise ValueError(f"unexpected NUL byte in text input: {name}")
            text.decode("utf-8")
        snapshot.seek(0)
        members.append(Member(name, mode, size, digest.hexdigest(), snapshot))
        remaining -= size
    return members


class BoundedOutput:
    def __init__(self, destination):
        self.destination = destination
        self.written = 0

    def write(self, data):
        if self.written + len(data) > MAX_ARCHIVE_BYTES:
            raise ValueError("compressed package exceeds the size limit")
        written = self.destination.write(data)
        if written != len(data):
            raise OSError("short archive write")
        self.written += written
        return written


class SingleGzip:
    """Read a bounded, single gzip member while hashing the compressed bytes."""

    def __init__(self, source, length):
        self.source = source
        self.remaining = length
        self.digest = hashlib.sha256()
        self.inflater = zlib.decompressobj(wbits=31)
        self.pending = self.read_compressed(len(GZIP_HEADER))
        if self.pending != GZIP_HEADER:
            raise ValueError("noncanonical gzip header")

    def read_compressed(self, limit):
        count = min(self.remaining, limit)
        chunk = self.source.read(count)
        if len(chunk) != count:
            raise ValueError("truncated compressed package")
        self.remaining -= len(chunk)
        self.digest.update(chunk)
        return chunk

    def read(self, size):
        result = bytearray()
        while len(result) < size and not self.inflater.eof:
            if not self.pending:
                self.pending = self.read_compressed(CHUNK)
            result.extend(self.inflater.decompress(self.pending, size - len(result)))
            self.pending = self.inflater.unconsumed_tail
            if self.inflater.eof:
                if self.inflater.unused_data or self.pending or self.remaining:
                    raise ValueError("trailing bytes or extra gzip member")
            elif not self.pending and not self.remaining and len(result) < size:
                raise ValueError("truncated gzip member")
        return bytes(result)


def verify_contents(source, length, members):
    stream = SingleGzip(source, length)
    consumed = 0
    for member in members:
        header = member.tarinfo().tobuf(format=tarfile.USTAR_FORMAT)
        if stream.read(tarfile.BLOCKSIZE) != header:
            raise ValueError(f"unexpected USTAR header or member order: {member.path}")
        todo = member.length
        digest = hashlib.sha256()
        while todo:
            count = min(todo, CHUNK)
            chunk = stream.read(count)
            if len(chunk) != count:
                raise ValueError(f"truncated archive member: {member.path}")
            digest.update(chunk)
            todo -= count
        if digest.hexdigest() != member.sha256:
            raise ValueError(f"archive member differs from its source: {member.path}")
        pad = (-member.length) % tarfile.BLOCKSIZE
        if stream.read(pad) != bytes(pad):
            raise ValueError(f"nonzero or missing member padding: {member.path}")
        consumed += tarfile.BLOCKSIZE + member.length + pad
    # USTAR terminates with two empty blocks. The writer pads the record to
    # tarfile.RECORDSIZE, and the verifier requires this exact end-of-archive.
    end = 2 * tarfile.BLOCKSIZE
    tail = end + (-(consumed + end)) % tarfile.RECORDSIZE
    if stream.read(tail) != bytes(tail) or stream.read(1):
        raise ValueError("invalid USTAR end or extra archive member")
    return stream.digest.hexdigest()


def evidence_bytes(name, length, sha256, platform, version, members):
    facts = {
        "schemaVersion": 1,
        "platform": platform,
        "version": version,
        "archive": {"name": name, "length": length, "sha256": sha256},
        "members": [member.evidence() for member in members],
    }
    return (json.dumps(facts, sort_keys=True, indent=2) + "\n").encode()


def package(args):
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}", args.version):
        raise ValueError("version must be a canonical numeric triplet")
    stem = f"nodomi-agent-{args.version}-{args.platform}"
    archive_path = args.output_dir / (stem + ".tar.gz")
    evidence_path = args.output_dir / (stem + ".verification.json")
    with contextlib.ExitStack() as stack:
        members = snapshot_members(args.root, args.bin_dir, args.license, args.platform, stack)
        staged_archive = None
        if args.command == "pack":
            args.output_dir.mkdir(parents=True, exist_ok=True)
            staged_archive = stack.enter_context(tempfile.NamedTemporaryFile(dir=args.output_dir))
            destination = BoundedOutput(staged_archive)
            with gzip.GzipFile(filename="", mode="wb", compresslevel=9,
                               fileobj=destination, mtime=0) as compressed:
                with tarfile.open(mode="w", fileobj=compressed, format=tarfile.USTAR_FORMAT) as archive:
                    for member in members:
                        archive.addfile(member.tarinfo(), member.snapshot)
            staged_archive.flush()
            os.fsync(staged_archive.fileno())
            staged_archive.seek(0)
            length = destination.written
            digest = verify_contents(staged_archive, length, members)
        else:
            with open_regular(archive_path, len(GZIP_HEADER), MAX_ARCHIVE_BYTES) as (archive, length):
                digest = verify_contents(archive, length, members)

        with tempfile.TemporaryDirectory(dir=args.output_dir) as evidence_directory:
            staged_evidence = Path(evidence_directory) / "verification.json"
            with staged_evidence.open("xb") as output:
                output.write(evidence_bytes(archive_path.name, length, digest,
                                            args.platform, args.version, members))
                output.flush()
                os.fsync(output.fileno())
            if staged_archive is None:
                os.replace(staged_evidence, evidence_path)
            else:
                os.link(staged_archive.name, archive_path)
                try:
                    os.link(staged_evidence, evidence_path)
                except OSError:
                    if os.path.samestat(os.fstat(staged_archive.fileno()), archive_path.lstat()):
                        archive_path.unlink()
                    raise

    print(archive_path.name)
    print(evidence_path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("pack", "verify"))
    parser.add_argument("--platform", choices=ELF_MACHINES, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--license", type=Path, required=True, help="combined package LICENSE")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        package(args)
    except (OSError, ValueError, zlib.error, tarfile.TarError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
