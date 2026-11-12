"""Build ordinary Agent release manifests from verified workflow facts."""

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


PLATFORMS = ("linux-x86_64", "linux-aarch64")
REPOSITORY = "DashunLiu/Nodomio"

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_U64 = (1 << 64) - 1
_MAX_PACKAGE_BYTES = 512 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_TAG_PART = r"(?:0|[1-9][0-9]{0,4})"
_AGENT_TAG = re.compile(rf"agent-v({_TAG_PART}\.{_TAG_PART}\.{_TAG_PART})")
_ABI_PART = r"(?:0|[1-9][0-9]{0,19})"
_ABI_VERSION = re.compile(rf"{_ABI_PART}\.{_ABI_PART}\.{_ABI_PART}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ASSET_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,199}")
_COMPATIBILITY_ARRAYS = (
    "wireProtocols",
    "supervisorProtocols",
    "readConfigFormats",
    "readQueueFormats",
)
_COMPATIBILITY_FIELDS = frozenset(
    (
        *_COMPATIBILITY_ARRAYS,
        "writeConfigFormat",
        "writeQueueFormat",
        "minKernel",
        "libc",
        "minLibcVersion",
    )
)


@dataclass(frozen=True)
class FileFacts:
    name: str
    length: int
    sha256: str


@dataclass(frozen=True)
class BuildFacts:
    tag: str
    commit: str
    platform: str
    is_security_update: bool
    compatibility: Mapping[str, object]
    package: FileFacts


@dataclass(frozen=True)
class GithubDraftFacts:
    id: int
    tag: str
    commit: str


@dataclass(frozen=True)
class UploadedAssetFacts:
    id: int
    name: str
    length: int
    sha256: str


def version_for_tag(tag: str) -> str:
    match = _AGENT_TAG.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        raise ValueError("invalid Agent release tag")
    return match[1]


def _asset_stem(tag: str, platform: str) -> str:
    if platform not in PLATFORMS:
        raise ValueError("unsupported Agent release platform")
    return f"nodomi-agent-{version_for_tag(tag)}-{platform}"


def package_name(tag: str, platform: str) -> str:
    return _asset_stem(tag, platform) + ".tar.gz"


def manifest_name(tag: str, platform: str) -> str:
    return _asset_stem(tag, platform) + ".release.json"


def _positive_integer(value: object, maximum: int = _MAX_SAFE_INTEGER) -> bool:
    return type(value) is int and 1 <= value <= maximum


def _check_commit(commit: str) -> None:
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise ValueError("expected a full lowercase Git commit hash")


def _check_file(file: FileFacts | UploadedAssetFacts) -> None:
    if not isinstance(file.name, str) or _ASSET_NAME.fullmatch(file.name) is None:
        raise ValueError("invalid release asset name")
    max_length = _MAX_MANIFEST_BYTES if file.name.endswith(".release.json") else _MAX_PACKAGE_BYTES
    if not _positive_integer(file.length, max_length):
        raise ValueError("invalid release asset length")
    if not isinstance(file.sha256, str) or _SHA256.fullmatch(file.sha256) is None:
        raise ValueError("expected a lowercase SHA-256 digest")


def _check_abi_version(value: object, field: str) -> None:
    if (
        not isinstance(value, str)
        or _ABI_VERSION.fullmatch(value) is None
        or any(int(part) > _MAX_U64 for part in value.split("."))
    ):
        raise ValueError(f"invalid compatibility field {field}")


def _compatibility_record(compatibility: Mapping[str, object]) -> dict:
    if not isinstance(compatibility, Mapping) or compatibility.keys() != _COMPATIBILITY_FIELDS:
        raise ValueError("unexpected Agent compatibility fields")

    record = dict(compatibility)
    for field in _COMPATIBILITY_ARRAYS:
        values = record[field]
        if (
            not isinstance(values, (list, tuple))
            or not 1 <= len(values) <= 16
            or any(not _positive_integer(value) for value in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError(f"invalid compatibility field {field}")
        record[field] = list(values)
    if 1 not in record["wireProtocols"]:
        raise ValueError("Agent release must support wire protocol 1")
    for written, readable in (
        ("writeConfigFormat", "readConfigFormats"),
        ("writeQueueFormat", "readQueueFormats"),
    ):
        if not _positive_integer(record[written]) or record[written] not in record[readable]:
            raise ValueError(f"compatibility field {written} is not readable")

    _check_abi_version(record["minKernel"], "minKernel")
    libc, min_libc = record["libc"], record["minLibcVersion"]
    if libc in ("GLIBC", "MUSL"):
        _check_abi_version(min_libc, "minLibcVersion")
    elif libc != "STATIC" or min_libc is not None:
        raise ValueError("invalid libc compatibility declaration")
    return record


def _check_build(build: BuildFacts) -> dict:
    _check_commit(build.commit)
    if type(build.is_security_update) is not bool:
        raise ValueError("invalid security update flag")
    if not isinstance(build.package, FileFacts):
        raise ValueError("invalid build package facts")
    _check_file(build.package)
    if build.package.name != package_name(build.tag, build.platform):
        raise ValueError("package name does not match the build tag and platform")
    return _compatibility_record(build.compatibility)


def check_builds(builds: Iterable[BuildFacts]) -> None:
    builds = tuple(builds)
    if len(builds) != len(PLATFORMS):
        raise ValueError("both Agent platform builds are required")
    for build in builds:
        _check_build(build)
    if {build.platform for build in builds} != set(PLATFORMS):
        raise ValueError("expected one build for each Agent platform")
    if len({(build.tag, build.commit, build.is_security_update) for build in builds}) != 1:
        raise ValueError("Agent builds disagree on the tag, commit or security update flag")


def _check_uploaded(asset: UploadedAssetFacts) -> None:
    if not _positive_integer(asset.id):
        raise ValueError("invalid GitHub asset ID")
    _check_file(asset)


def _assets_by_name(assets: Iterable[UploadedAssetFacts]) -> dict[str, UploadedAssetFacts]:
    indexed = {}
    ids = set()
    for asset in assets:
        _check_uploaded(asset)
        if asset.name in indexed or asset.id in ids:
            raise ValueError("duplicate release asset name or ID")
        indexed[asset.name] = asset
        ids.add(asset.id)
    return indexed


def check_assets(expected: dict[str, UploadedAssetFacts], observed: list[UploadedAssetFacts]) -> None:
    if _assets_by_name(expected.values()) != expected or _assets_by_name(observed) != expected:
        raise ValueError("GitHub release assets differ from the expected set")


def make_manifest(
    build: BuildFacts, release: GithubDraftFacts, artifact: UploadedAssetFacts
) -> dict:
    compatibility = _check_build(build)
    if not _positive_integer(release.id):
        raise ValueError("invalid GitHub release ID")
    _check_commit(release.commit)
    if release.tag != build.tag or release.commit != build.commit:
        raise ValueError("GitHub draft tag or commit differs from the build")
    _check_uploaded(artifact)
    if FileFacts(artifact.name, artifact.length, artifact.sha256) != build.package:
        raise ValueError("GitHub program asset differs from the local package")

    version = version_for_tag(build.tag)
    major, minor, patch = map(int, version.split("."))
    release_url = f"https://github.com/{REPOSITORY}/releases/{release.id}"
    owner, repo = REPOSITORY.split("/")
    return {
        "length": artifact.length,
        "hashes": {"sha256": artifact.sha256},
        "custom": {
            "nodomi": {
                "schemaVersion": 1,
                "component": "AGENT",
                "releaseId": str(uuid.uuid5(uuid.NAMESPACE_URL, release_url)),
                "sequence": 1 + major * 10_000_000_000 + minor * 100_000 + patch,
                "version": version,
                "channel": "STABLE",
                "platform": build.platform,
                "isSecurityUpdate": build.is_security_update,
                "compatibility": compatibility,
                "github": {
                    "owner": owner,
                    "repo": repo,
                    "releaseId": release.id,
                    "assetId": artifact.id,
                    "assetName": artifact.name,
                },
                "status": "ACTIVE",
            },
        },
    }
