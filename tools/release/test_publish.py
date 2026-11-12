import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from agent_manifest import PLATFORMS, package_name
from agent_publish import PublishError
import publish


TAG = "agent-v0.1.0"
COMMIT = "a" * 40
RUN_ID = 42
COMPATIBILITY = {
    "wireProtocols": [1], "supervisorProtocols": [1],
    "readConfigFormats": [1], "writeConfigFormat": 1,
    "readQueueFormats": [1], "writeQueueFormat": 1,
    "minKernel": "5.10.0", "libc": "STATIC", "minLibcVersion": None,
}


def write_artifacts(root):
    hashes = {}
    for platform in PLATFORMS:
        directory = root / f"nodomi-agent-publish-{platform}"
        directory.mkdir()
        name = package_name(TAG, platform)
        data = platform.encode()
        (directory / name).write_bytes(data)
        digest = hashes[platform] = hashlib.sha256(data).hexdigest()
        (directory / "build.json").write_text(json.dumps({
            "tag": TAG, "commit": COMMIT, "platform": platform,
            "is_security_update": False, "compatibility": COMPATIBILITY,
            "package": {"name": name, "length": len(data), "sha256": digest},
        }), encoding="utf-8")
    return hashes


class ReviewedPublishTests(unittest.TestCase):
    def test_operator_reuses_exact_run_and_download_then_publishes_reviewed_bytes(self):
        hashes = {platform: hashlib.sha256(platform.encode()).hexdigest() for platform in PLATFORMS}
        calls = []
        api = Mock()
        api.verify_build_run.side_effect = lambda *args: calls.append(("run", *args))

        def download(run, directory, token):
            calls.append(("download", run, token))
            write_artifacts(directory)

        def mutate(bound_api, builds, packages):
            calls.append(("publish",))
            self.assertIs(bound_api, api)
            self.assertEqual({item.platform: item.package.sha256 for item in builds}, hashes)
            self.assertEqual(
                {platform: hashlib.sha256(package.read_bytes()).hexdigest()
                 for platform, package in packages.items()},
                hashes,
            )
            return 321

        with (
            patch.dict(os.environ, {"GH_TOKEN": "fixture"}, clear=True),
            patch.object(publish, "GithubReleaseApi", return_value=api),
            patch.object(publish, "_download_artifacts", side_effect=download),
            patch.object(publish, "publish_agent", side_effect=mutate),
        ):
            self.assertEqual(publish.publish_reviewed(RUN_ID, TAG, COMMIT, False, hashes), 321)
        self.assertEqual(calls, [("run", RUN_ID, COMMIT), ("download", RUN_ID, "fixture"), ("publish",)])

    def test_failed_run_never_downloads_or_publishes(self):
        api = Mock()
        api.verify_build_run.side_effect = PublishError("wrong run")
        with (
            patch.dict(os.environ, {"GH_TOKEN": "fixture"}, clear=True),
            patch.object(publish, "GithubReleaseApi", return_value=api),
            patch.object(publish, "_download_artifacts") as download,
            patch.object(publish, "publish_agent") as mutate,
            self.assertRaisesRegex(PublishError, "wrong run"),
        ):
            publish.publish_reviewed(RUN_ID, TAG, COMMIT, False, dict.fromkeys(PLATFORMS, "b" * 64))
        download.assert_not_called()
        mutate.assert_not_called()

    def test_unreviewed_hash_wrong_source_and_extra_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = write_artifacts(root)
            with self.assertRaises(PublishError):
                publish.reviewed_builds(root, TAG, "b" * 40, False, hashes)
            with self.assertRaises(PublishError):
                publish.reviewed_builds(root, TAG, COMMIT, True, hashes)
            with self.assertRaises(PublishError):
                publish.reviewed_builds(root, TAG, COMMIT, False, hashes | {PLATFORMS[0]: "b" * 64})
            (root / f"nodomi-agent-publish-{PLATFORMS[0]}" / "extra").touch()
            with self.assertRaises(PublishError):
                publish.reviewed_builds(root, TAG, COMMIT, False, hashes)

    def test_download_selects_both_fixed_names_from_exact_run(self):
        with patch.object(subprocess, "run") as run:
            publish._download_artifacts(RUN_ID, Path("/reviewed-temp"), "fixture")
        args, kwargs = run.call_args
        self.assertEqual(args[0], [
            "gh", "run", "download", str(RUN_ID), "--repo", "github.com/DashunLiu/Nodomio",
            "--name", "nodomi-agent-publish-linux-x86_64",
            "--name", "nodomi-agent-publish-linux-aarch64", "--dir", "/reviewed-temp",
        ])
        self.assertEqual(kwargs["env"]["GH_TOKEN"], "fixture")
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)

    def test_gh_fallback_reads_token_without_printing_or_adding_command_args(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(subprocess, "run", return_value=Mock(stdout="fixture\n")) as run,
        ):
            self.assertEqual(publish._github_token(), "fixture")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["gh", "auth", "token", "--hostname", "github.com"])
        self.assertTrue(kwargs["capture_output"])
