import gzip
import hashlib
import io
import json
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("package_agent.py")
STEM = "nodomi-agent-0.1.0-linux-aarch64"
BINARIES = ("nodomi-agent", "nodomi-agentctl", "nodomi-agent-supervisor")


def compress(data):
    stream = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as writer:
        writer.write(data)
    return stream.getvalue()


def elf(machine=183, extra_type=0, dynamic_tag=0):
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     2, machine, 1, 0x400080, 64, 0, 0, 64, 56,
                     2 if extra_type else 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0,
                     len(data), len(data), 4096)
    if extra_type:
        struct.pack_into("<IIQQQQQQ", data, 120, extra_type, 4, 208,
                         0x4000D0, 0, 32, 32, 8)
        struct.pack_into("<qQ", data, 208, dynamic_tag, 1)
    return data


class PackageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.bins = self.root / "bin"
        self.bins.mkdir()
        for name in BINARIES:
            (self.bins / name).write_bytes(elf())
        self.inputs = {
            "deploy/agent/systemd/nodomi-agent.service": b"[Service]\n",
            "deploy/agent/openrc/nodomi-agent": b"#!/sbin/openrc-run\n",
            "LICENSE": b"Fixture license text\n",
        }
        for name, contents in self.inputs.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)

    def call(self, action, directory):
        return subprocess.run(
            [sys.executable, SCRIPT, action, "--root", self.root, "--platform", "linux-aarch64",
             "--version", "0.1.0", "--bin-dir", self.bins, "--license", self.root / "LICENSE",
             "--output-dir", directory],
            capture_output=True, text=True,
        )

    def pack(self):
        output = self.root / "out"
        result = self.call("pack", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_pack_is_reproducible_and_verifies_exact_members(self):
        output = self.pack()
        other = self.root / "other"
        result = self.call("pack", other)
        self.assertEqual(result.returncode, 0, result.stderr)
        package = (output / (STEM + ".tar.gz")).read_bytes()
        self.assertEqual(package, (other / (STEM + ".tar.gz")).read_bytes())
        evidence = json.loads((output / (STEM + ".verification.json")).read_bytes())
        self.assertEqual(evidence["archive"], {
            "name": STEM + ".tar.gz", "length": len(package),
            "sha256": hashlib.sha256(package).hexdigest(),
        })
        with tarfile.open(fileobj=io.BytesIO(package), mode="r:gz") as archive:
            self.assertEqual([item.name for item in archive], [
                *["bin/" + name for name in BINARIES],
                "services/systemd/nodomi-agent.service", "services/openrc/nodomi-agent", "LICENSE",
            ])
            self.assertEqual([item.mode for item in archive], [0o755] * 3 + [0o644, 0o755, 0o644])
            for item, facts in zip(archive.getmembers(), evidence["members"], strict=True):
                self.assertEqual(facts["path"], item.name)
                self.assertEqual(facts["mode"], f"{item.mode:04o}")
                self.assertEqual(facts["sha256"], hashlib.sha256(archive.extractfile(item).read()).hexdigest())
        result = self.call("verify", output)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verify_rejects_member_extra_gzip_and_changed_inputs(self):
        output = self.pack()
        archive = output / (STEM + ".tar.gz")
        good = archive.read_bytes()
        unpacked = gzip.decompress(good)
        with tarfile.open(fileobj=io.BytesIO(unpacked)) as decoded:
            license_entry = decoded.getmembers()[-1]
        end = license_entry.offset_data + license_entry.size
        end += (-end) % tarfile.BLOCKSIZE
        extra = tarfile.TarInfo("unexpected").tobuf(format=tarfile.USTAR_FORMAT)
        for altered in (
            good + compress(b""),
            good + b"\0",
            good[:-1],
            compress(b"../" + unpacked[3:]),
            compress(unpacked[:512] + b"X" + unpacked[513:]),
            compress(unpacked[:end] + extra + unpacked[end + len(extra):]),
        ):
            archive.write_bytes(altered)
            self.assertNotEqual(self.call("verify", output).returncode, 0)
        archive.write_bytes(good)
        (self.root / "LICENSE").write_bytes(b"Different approved bytes\n")
        self.assertNotEqual(self.call("verify", output).returncode, 0)

    def test_pack_rejects_wrong_machine_loader_needed_and_symlink(self):
        binary = self.bins / BINARIES[0]
        for bad in (elf(machine=62), elf(extra_type=3), elf(extra_type=2, dynamic_tag=1)):
            binary.write_bytes(bad)
            self.assertNotEqual(self.call("pack", self.root / "out").returncode, 0)
        binary.unlink()
        binary.symlink_to(BINARIES[1])
        self.assertNotEqual(self.call("pack", self.root / "out").returncode, 0)

    def test_license_limit_is_independent_of_both_service_limits(self):
        license_file = self.root / "LICENSE"
        license_bytes = b"L" * (1024 * 1024)
        license_file.write_bytes(license_bytes)
        service_files = [self.root / name for name in self.inputs if name != "LICENSE"]
        service_bytes = b"S" * (64 * 1024)
        for path in service_files:
            path.write_bytes(service_bytes)
        output = self.pack()
        result = self.call("verify", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((output / (STEM + ".verification.json")).read_bytes())
        self.assertEqual(evidence["members"][-1]["length"], len(license_bytes))

        invalid_output = self.root / "invalid"
        license_file.write_bytes(license_bytes + b"L")
        self.assertNotEqual(self.call("pack", invalid_output).returncode, 0)
        license_file.write_bytes(license_bytes)
        for path in service_files:
            with self.subTest(service=path.name):
                path.write_bytes(service_bytes + b"S")
                self.assertNotEqual(self.call("pack", invalid_output).returncode, 0)
                path.write_bytes(service_bytes)


if __name__ == "__main__":
    unittest.main()
