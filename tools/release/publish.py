"""Publish the exact packages reviewed from one successful Agent build run."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from agent_manifest import PLATFORMS, REPOSITORY, BuildFacts, FileFacts, check_builds, version_for_tag
from agent_publish import GithubReleaseApi, PublishError, _commit_sha, _id, _unique_fields, publish_agent


_RECORD_LIMIT = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ARTIFACT_NAMES = {platform: f"nodomi-agent-publish-{platform}" for platform in PLATFORMS}


def _github_cli_environment():
    return dict(os.environ, GH_HOST="github.com", GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1")


def _github_token():
    if token := os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            env=_github_cli_environment(), check=True, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise PublishError("could not read the current GitHub CLI authorization") from None
    return result.stdout.strip()


def _download_artifacts(run_id, root, token):
    command = ["gh", "run", "download", str(run_id), "--repo", f"github.com/{REPOSITORY}"]
    for artifact in _ARTIFACT_NAMES.values():
        command.extend(("--name", artifact))
    command.extend(("--dir", os.fspath(root)))
    try:
        subprocess.run(
            command, env=dict(_github_cli_environment(), GH_TOKEN=token),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=600,
        )
    except (OSError, subprocess.SubprocessError):
        raise PublishError("could not download both artifacts from the reviewed build run") from None


def _build_record(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise PublishError("Agent build record must be a regular file")
        raw = source.read(_RECORD_LIMIT + 1)
    if len(raw) > _RECORD_LIMIT:
        raise PublishError("Agent build record exceeds the size limit")
    try:
        fields = json.loads(raw, object_pairs_hook=_unique_fields)
        if type(fields) is not dict or type(fields.get("package")) is not dict:
            raise ValueError("invalid build record")
        package = FileFacts(**fields.pop("package"))
        return BuildFacts(package=package, **fields)
    except (TypeError, ValueError, RecursionError):
        raise PublishError("Agent build record has invalid fields") from None


def reviewed_builds(root, tag, commit, security_update, expected_hashes):
    if {entry.name for entry in root.iterdir()} != set(_ARTIFACT_NAMES.values()):
        raise PublishError("download did not contain the exact two Agent artifacts")
    builds, packages = [], {}
    for platform, name in _ARTIFACT_NAMES.items():
        directory = root / name
        if directory.is_symlink() or not directory.is_dir():
            raise PublishError("Agent artifact must be an extracted directory")
        build = _build_record(directory / "build.json")
        if (
            build.tag != tag or build.commit != commit or build.platform != platform
            or build.is_security_update is not security_update
            or build.package.sha256 != expected_hashes[platform]
        ):
            raise PublishError("Agent build record differs from the reviewed build facts")
        builds.append(build)
    check_builds(builds)
    for build in builds:
        directory = root / _ARTIFACT_NAMES[build.platform]
        if {entry.name for entry in directory.iterdir()} != {"build.json", build.package.name}:
            raise PublishError("Agent artifact did not contain exactly its record and package")
        packages[build.platform] = directory / build.package.name
    return builds, packages


def publish_reviewed(run_id, tag, commit, security_update, expected_hashes):
    _id(run_id)
    version_for_tag(tag)
    _commit_sha(commit)
    if set(expected_hashes) != set(PLATFORMS) or any(
        not isinstance(value, str) or _SHA256.fullmatch(value) is None
        for value in expected_hashes.values()
    ):
        raise PublishError("both reviewed lowercase package SHA-256 digests are required")
    token = _github_token()
    api = GithubReleaseApi(token)
    api.verify_build_run(run_id, commit)
    with tempfile.TemporaryDirectory(prefix="nodomi-reviewed-release-") as directory:
        root = Path(directory)
        _download_artifacts(run_id, root, token)
        builds, packages = reviewed_builds(root, tag, commit, security_update, expected_hashes)
        return publish_agent(api, builds, packages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, required=True, help="reviewed GitHub Actions run ID")
    parser.add_argument("--tag", required=True, help="existing Agent tag pointing to the reviewed commit")
    parser.add_argument("--commit", required=True, help="exact reviewed commit SHA")
    parser.add_argument("--security-update", choices=("true", "false"), required=True)
    parser.add_argument("--sha256-x86-64", required=True, help="reviewed x86-64 package digest")
    parser.add_argument("--sha256-aarch64", required=True, help="reviewed ARM64 package digest")
    args = parser.parse_args()
    try:
        release_id = publish_reviewed(
            args.run_id, args.tag, args.commit, args.security_update == "true",
            {"linux-x86_64": args.sha256_x86_64, "linux-aarch64": args.sha256_aarch64},
        )
    except (PublishError, ValueError) as error:
        print(f"Agent release: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("Agent release: could not inspect the downloaded build artifacts", file=sys.stderr)
        return 1
    print(f"Verified immutable release: https://github.com/{REPOSITORY}/releases/{release_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
