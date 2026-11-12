"""Publish a complete Agent release to the official GitHub repository."""

import hashlib
import http.client
import json
import os
import re
import stat
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import BinaryIO
from urllib.parse import parse_qs, quote, urlsplit

from agent_manifest import (
    PLATFORMS,
    REPOSITORY,
    BuildFacts,
    FileFacts,
    GithubDraftFacts,
    UploadedAssetFacts,
    check_assets,
    check_builds,
    make_manifest,
    manifest_name,
    version_for_tag,
)


_API_HOST = "api.github.com"
_UPLOAD_HOST = "uploads.github.com"
_REPO_PATH = f"/repos/{REPOSITORY}"
_API_VERSION = "2022-11-28"
_MAX_CONTROL_BYTES = 2 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_PACKAGE_BYTES = 512 * 1024 * 1024
_PAGE_SIZE = 100
_MAX_PAGES = 5
_MAX_ASSETS = 16
_MAX_TAG_OBJECTS = 4
_BUILD_WORKFLOW = ".github/workflows/agent-build.yml"
_ASSET_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")


class PublishError(RuntimeError):
    pass


class RequestOutcomeUnknown(PublishError):
    pass


@dataclass(frozen=True)
class GithubReleaseRecord:
    id: int
    tag: str
    draft: bool
    prerelease: bool
    immutable: bool | None
    published_at: str | None
    upload_url: str


class GithubReleaseApi:
    def __init__(self, token: str, settings_token: str | None = None):
        for value in (token, settings_token if settings_token is not None else token):
            if not isinstance(value, str) or re.fullmatch(r"[!-~]+", value) is None:
                raise PublishError("a GitHub token is missing or malformed")
        self._token = token
        self._settings_token = settings_token if settings_token is not None else token

    def immutable_enabled(self) -> bool:
        result, _ = self._request("GET", "/immutable-releases", 200, settings=True)
        return _object(result).get("enabled") is True

    def verify_build_run(self, run_id: int, commit: str) -> None:
        body, _ = self._request("GET", f"/actions/runs/{_id(run_id)}", 200)
        run = _object(body)
        repository = _object(run.get("repository"))
        head_repository = _object(run.get("head_repository"))
        if (
            _id(run.get("id")) != run_id or run.get("head_sha") != _commit_sha(commit)
            or run.get("head_branch") != "main" or run.get("event") != "workflow_dispatch"
            or run.get("path") not in (_BUILD_WORKFLOW, f"{_BUILD_WORKFLOW}@main",
                                      f"{_BUILD_WORKFLOW}@refs/heads/main")
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or repository.get("full_name") != REPOSITORY
            or head_repository.get("full_name") != REPOSITORY
            or _id(repository.get("id")) != _id(head_repository.get("id"))
        ):
            raise PublishError("reviewed run is not a successful Agent build of the exact source")

    def find_releases(self, tag: str) -> list[GithubReleaseRecord]:
        version_for_tag(tag)
        matches = []
        seen = set()
        for page in range(1, _MAX_PAGES + 1):
            body, headers = self._request("GET", f"/releases?per_page={_PAGE_SIZE}&page={page}", 200)
            entries = _array(body, _PAGE_SIZE)
            has_next = _has_next(headers, "/releases", page)
            if not entries and has_next:
                raise PublishError("GitHub release catalog is incomplete")
            for entry in entries:
                record = _object(entry)
                entry_id = _id(record.get("id"))
                entry_tag = record.get("tag_name")
                if entry_id in seen or not isinstance(entry_tag, str):
                    raise PublishError("GitHub release catalog changed or is malformed")
                seen.add(entry_id)
                if entry_tag == tag:
                    matches.append(_release_record(record))
            if not has_next:
                return matches
        raise PublishError("GitHub release catalog exceeds the page limit")

    def get_release(self, release_id: int) -> GithubReleaseRecord:
        body, _ = self._request("GET", f"/releases/{_id(release_id)}", 200)
        record = _release_record(body)
        if record.id != release_id:
            raise PublishError("GitHub returned a different release ID")
        return record

    def tag_commit(self, tag: str) -> str:
        version_for_tag(tag)
        body, _ = self._request("GET", f"/git/ref/tags/{tag}", 200)
        reference = _object(body)
        if reference.get("ref") != f"refs/tags/{tag}":
            raise PublishError("GitHub returned a different tag ref")
        target = _object(reference.get("object"))
        seen = set()
        for _ in range(_MAX_TAG_OBJECTS + 1):
            sha = _commit_sha(target.get("sha"))
            kind = target.get("type")
            if kind == "commit":
                return sha
            if kind != "tag" or sha in seen or len(seen) == _MAX_TAG_OBJECTS:
                break
            seen.add(sha)
            body, _ = self._request("GET", f"/git/tags/{sha}", 200)
            annotation = _object(body)
            if annotation.get("sha") != sha:
                raise PublishError("GitHub returned a different tag object")
            target = _object(annotation.get("object"))
        raise PublishError("GitHub tag did not resolve to a commit within the tag limit")

    def create_draft(self, tag: str, commit: str) -> GithubReleaseRecord:
        version_for_tag(tag)
        try:
            body, _ = self._request("POST", "/releases", 201, payload={
                "tag_name": tag, "target_commitish": _commit_sha(commit),
                "draft": True, "prerelease": False, "make_latest": "false",
            })
        except RequestOutcomeUnknown:
            raise RequestOutcomeUnknown(f"could not confirm GitHub draft creation for {tag}") from None
        try:
            return _release_record(body)
        except PublishError:
            raise RequestOutcomeUnknown(f"could not confirm GitHub draft creation for {tag}") from None

    def list_assets(self, release_id: int) -> list[UploadedAssetFacts]:
        path = f"/releases/{_id(release_id)}/assets"
        body, headers = self._request("GET", f"{path}?per_page={_PAGE_SIZE}", 200)
        if _has_next(headers, path, 1):
            raise PublishError("GitHub release asset list is paginated")
        return [_asset_record(item) for item in _array(body, _MAX_ASSETS)]

    def upload_asset(
        self, release: GithubReleaseRecord, source: BinaryIO, facts: FileFacts
    ) -> UploadedAssetFacts:
        path = f"/releases/{_id(release.id)}/assets"
        if release.upload_url != f"https://{_UPLOAD_HOST}{_REPO_PATH}{path}{{?name,label}}":
            raise PublishError("GitHub returned an unexpected release upload URL")
        try:
            body, _ = self._request(
                "POST", f"{path}?name={quote(facts.name, safe='')}", 201,
                upload=(source, facts),
            )
        except RequestOutcomeUnknown:
            raise RequestOutcomeUnknown(f"could not confirm asset upload to GitHub draft {release.id}") from None
        try:
            return _asset_record(body)
        except PublishError:
            raise RequestOutcomeUnknown(f"could not confirm asset upload to GitHub draft {release.id}") from None

    def verify_asset_bytes(self, asset: UploadedAssetFacts) -> None:
        """Re-read the exact asset ID, never sending the token to an asset CDN."""
        host, path = _API_HOST, f"{_REPO_PATH}/releases/assets/{_id(asset.id)}"
        headers = {
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "nodomi-agent-release",
        }
        for _ in range(4):
            request_headers = dict(headers)
            if host == _API_HOST:
                request_headers["Authorization"] = f"Bearer {self._token}"
                request_headers["X-GitHub-Api-Version"] = _API_VERSION
            connection = http.client.HTTPSConnection(host, timeout=60)
            try:
                connection.request("GET", path, headers=request_headers)
                response = connection.getresponse()
                if response.status == 200:
                    _verify_asset_response(response, asset)
                    return
                if response.status not in (301, 302, 303, 307, 308):
                    raise PublishError(f"GitHub asset readback failed (HTTP {response.status})")
                host, path = _asset_redirect(_single_header(response, "Location"))
            except (OSError, http.client.HTTPException):
                raise PublishError("GitHub asset readback transport failed") from None
            finally:
                connection.close()
        raise PublishError("GitHub asset readback exceeded its redirect limit")

    def publish_draft(self, release_id: int) -> None:
        try:
            self._request(
                "PATCH", f"/releases/{_id(release_id)}", 200,
                payload={"draft": False, "make_latest": "false"}, read_json=False,
            )
        except RequestOutcomeUnknown:
            raise RequestOutcomeUnknown(f"could not confirm GitHub publish response for draft {release_id}") from None

    def _request(
        self, method, path, expected, *, payload=None, upload=None, settings=False, read_json=True
    ):
        host = _UPLOAD_HOST if upload is not None else _API_HOST
        token = self._settings_token if settings else self._token
        headers = {
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "identity",
            "Authorization": f"Bearer {token}",
            "User-Agent": "nodomi-agent-release",
            "X-GitHub-Api-Version": _API_VERSION,
        }
        body = None
        if upload is not None:
            body, facts = upload
            headers["Content-Type"] = (
                "application/json" if facts.name.endswith(".release.json") else "application/octet-stream"
            )
            headers["Content-Length"] = str(facts.length)
        elif payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        # Direct TLS with system roots. No proxy, redirect handling, or retry layer.
        connection = http.client.HTTPSConnection(host, timeout=60)
        try:
            connection.request(method, _REPO_PATH + path, body=body, headers=headers)
            response = connection.getresponse()
            if response.status != expected:
                if method != "GET" and response.status >= 500:
                    raise RequestOutcomeUnknown(f"GitHub {method} outcome is unknown (HTTP {response.status})")
                raise PublishError(f"GitHub {method} failed (HTTP {response.status})")
            if not read_json:
                return None, []
            raw = response.read(_MAX_CONTROL_BYTES + 1)
            response_headers = response.getheaders()
        except (OSError, http.client.HTTPException):
            error = PublishError if method == "GET" else RequestOutcomeUnknown
            raise error(f"GitHub {method} transport failed") from None
        finally:
            connection.close()

        if len(raw) > _MAX_CONTROL_BYTES:
            error = PublishError if method == "GET" else RequestOutcomeUnknown
            raise error("GitHub response exceeds the size limit")
        try:
            return json.loads(raw, object_pairs_hook=_unique_fields), response_headers
        except (ValueError, RecursionError):
            error = PublishError if method == "GET" else RequestOutcomeUnknown
            raise error("GitHub returned invalid JSON") from None


def _unique_fields(fields):
    result = dict(fields)
    if len(result) != len(fields):
        raise ValueError("duplicate field")
    return result


def _single_header(response, header):
    values = [value for name, value in response.getheaders() if name.lower() == header.lower()]
    if len(values) > 1:
        raise PublishError("GitHub asset response contains duplicate headers")
    return values[0] if values else None


def _asset_redirect(location):
    if (
        not isinstance(location, str) or len(location) > 8192
        or re.fullmatch(r"[!-~]+", location) is None or "\\" in location
    ):
        raise PublishError("GitHub asset redirect is invalid")
    try:
        target = urlsplit(location)
    except ValueError:
        raise PublishError("GitHub asset redirect is invalid") from None
    if (
        target.scheme != "https" or target.netloc not in _ASSET_HOSTS
        or not target.path.startswith("/") or "#" in location
    ):
        raise PublishError("GitHub asset redirect is invalid")
    return target.netloc, target.path + (f"?{target.query}" if target.query else "")


def _verify_asset_response(response, asset):
    length = _single_header(response, "Content-Length")
    encoding = _single_header(response, "Content-Encoding")
    if (
        type(asset.length) is not int or not 1 <= asset.length <= _MAX_PACKAGE_BYTES
        or length not in (None, str(asset.length)) or encoding not in (None, "identity")
    ):
        raise PublishError("GitHub asset response length or encoding is invalid")
    read = 0
    digest = hashlib.sha256()
    while chunk := response.read(min(1024 * 1024, asset.length - read + 1)):
        read += len(chunk)
        if read > asset.length:
            raise PublishError("GitHub asset readback exceeds the expected length")
        digest.update(chunk)
    if read != asset.length or digest.hexdigest() != asset.sha256:
        raise PublishError("GitHub asset bytes differ from the expected file")


def _object(value):
    if not isinstance(value, dict):
        raise PublishError("GitHub returned an invalid object")
    return value


def _array(value, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise PublishError("GitHub returned an invalid or oversized list")
    return value


def _id(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 9_007_199_254_740_991:
        raise PublishError("invalid GitHub ID")
    return value


def _commit_sha(value: object) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise PublishError("invalid GitHub commit or tag object ID")
    return value


def _release_record(value: object) -> GithubReleaseRecord:
    record = _object(value)
    tag, draft, prerelease = (record.get(key) for key in ("tag_name", "draft", "prerelease"))
    immutable, published_at, upload_url = (
        record.get(key) for key in ("immutable", "published_at", "upload_url")
    )
    if (
        not isinstance(tag, str) or type(draft) is not bool or type(prerelease) is not bool
        or (immutable is not None and type(immutable) is not bool)
        or "published_at" not in record
        or (published_at is not None and (not isinstance(published_at, str) or not published_at))
        or not isinstance(upload_url, str)
    ):
        raise PublishError("GitHub returned an invalid release record")
    return GithubReleaseRecord(_id(record.get("id")), tag, draft, prerelease, immutable, published_at, upload_url)


def _asset_record(value: object) -> UploadedAssetFacts:
    record = _object(value)
    name, length, digest = (record.get(key) for key in ("name", "size", "digest"))
    sha = _DIGEST.fullmatch(digest) if isinstance(digest, str) else None
    if (
        record.get("state") != "uploaded" or not isinstance(name, str)
        or type(length) is not int or length <= 0 or sha is None
    ):
        raise PublishError("GitHub returned an incomplete or invalid release asset")
    return UploadedAssetFacts(_id(record.get("id")), name, length, sha[1])


def _has_next(headers, endpoint, page):
    # GitHub may advertise a numeric repository alias. Requests always use the
    # fixed named repository, and only a validated consecutive page is requested.
    numeric = re.compile(rf"/repositories/[1-9][0-9]*{re.escape(endpoint)}")
    relations = {}
    try:
        for name, value in headers:
            if name.lower() != "link":
                continue
            for link in value.split(","):
                target, relation = re.fullmatch(
                    r'<([^<>]+)>;\s*rel="(first|prev|next|last)"', link.strip()
                ).groups()
                url = urlsplit(target)
                query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
                page_value, = query["page"]
                if (
                    url.scheme != "https" or url.netloc != _API_HOST or url.fragment
                    or (url.path != _REPO_PATH + endpoint and not numeric.fullmatch(url.path))
                    or relation in relations or set(query) != {"page", "per_page"}
                    or query["per_page"] != [str(_PAGE_SIZE)]
                    or not re.fullmatch(r"[1-9][0-9]*", page_value)
                ):
                    raise ValueError("invalid pagination link")
                relations[relation] = int(page_value)
        for relation, expected in (("first", 1), ("prev", page - 1), ("next", page + 1)):
            if relation in relations and relations[relation] != expected:
                raise ValueError("unexpected pagination page")
        has_next = "next" in relations
        last = relations.get("last")
        if last is not None and (last < page or (last > page) != has_next):
            raise ValueError("inconsistent pagination links")
        return has_next
    except (AttributeError, KeyError, ValueError):
        raise PublishError("GitHub pagination links are invalid") from None


def _stage_package(path: Path, facts: FileFacts, destination: BinaryIO) -> None:
    digest = hashlib.sha256()
    length = 0
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise PublishError("Agent package must be a regular file")
            while chunk := source.read(min(1024 * 1024, facts.length - length + 1)):
                length += len(chunk)
                if length > facts.length:
                    break
                digest.update(chunk)
                destination.write(chunk)
    except OSError:
        raise PublishError("could not read and stage an Agent package") from None
    if length != facts.length or digest.hexdigest() != facts.sha256:
        raise PublishError("local package bytes differ from the verified build")
    destination.seek(0)


def _require_draft(record: GithubReleaseRecord, release_id: int, tag: str) -> None:
    if (
        record.id != release_id or record.tag != tag or not record.draft
        or record.prerelease or record.immutable is True or record.published_at is not None
    ):
        raise PublishError("expected the same unpublished GitHub draft")


def _require_repository_state(api, tag, commit) -> None:
    if api.tag_commit(tag) != commit:
        raise PublishError("GitHub tag commit differs from the verified build")
    if api.immutable_enabled() is not True:
        raise PublishError("GitHub immutable releases are not confirmed enabled")


def _require_matching_file(asset: UploadedAssetFacts, facts: FileFacts) -> None:
    if FileFacts(asset.name, asset.length, asset.sha256) != facts:
        raise PublishError("GitHub asset differs from the expected file")


def _ensure_asset(api, draft, existing, source, facts):
    asset = existing.get(facts.name)
    if asset is None:
        asset = api.upload_asset(draft, source, facts)
    _require_matching_file(asset, facts)
    return asset


def _confirm_published(api, release_id, tag, commit, expected):
    current = api.get_release(release_id)
    if (
        current.id != release_id or current.tag != tag or current.draft or current.prerelease
        or current.immutable is not True or not current.published_at
    ):
        raise PublishError("GitHub did not confirm the same immutable published release")
    check_assets(expected, api.list_assets(release_id))
    if api.tag_commit(tag) != commit:
        raise PublishError("published GitHub tag commit differs from the verified build")


def publish_agent(
    api: GithubReleaseApi, builds: list[BuildFacts], packages: dict[str, Path]
) -> int:
    """Publish staged bytes once, and return the verified GitHub release ID."""
    check_builds(builds)
    if set(packages) != set(PLATFORMS):
        raise PublishError("both Agent package files are required")
    by_platform = {build.platform: build for build in builds}
    ordered = [by_platform[platform] for platform in PLATFORMS]
    tag, commit = ordered[0].tag, ordered[0].commit

    with ExitStack() as stack:
        staged = {}
        for build in ordered:
            target = stack.enter_context(tempfile.TemporaryFile("w+b"))
            _stage_package(packages[build.platform], build.package, target)
            staged[build.platform] = target

        _require_repository_state(api, tag, commit)
        matches = api.find_releases(tag)
        if len(matches) > 1:
            raise PublishError("more than one GitHub release matches the Agent tag")
        draft = matches[0] if matches else api.create_draft(tag, commit)
        release_id = _id(draft.id)
        _require_draft(draft, release_id, tag)
        draft = api.get_release(release_id)
        _require_draft(draft, release_id, tag)

        observed = api.list_assets(release_id)
        existing = {asset.name: asset for asset in observed}
        check_assets(existing, observed)
        manifest_names = {build.platform: manifest_name(tag, build.platform) for build in ordered}
        expected_names = {build.package.name for build in ordered} | set(manifest_names.values())
        if existing.keys() - expected_names:
            raise PublishError("GitHub draft has unexpected assets")
        for build in ordered:
            if build.package.name in existing:
                _require_matching_file(existing[build.package.name], build.package)
            elif manifest_names[build.platform] in existing:
                raise PublishError("GitHub draft manifest has no corresponding package")

        expected = {}
        for build in ordered:
            facts = build.package
            expected[facts.name] = _ensure_asset(api, draft, existing, staged[build.platform], facts)

        draft_facts = GithubDraftFacts(release_id, tag, commit)
        for build in ordered:
            manifest = make_manifest(build, draft_facts, expected[build.package.name])
            data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            if len(data) > _MAX_MANIFEST_BYTES:
                raise PublishError("Agent release manifest exceeds the size limit")
            facts = FileFacts(manifest_names[build.platform], len(data), hashlib.sha256(data).hexdigest())
            expected[facts.name] = _ensure_asset(api, draft, existing, BytesIO(data), facts)

        _require_draft(api.get_release(release_id), release_id, tag)
        check_assets(expected, api.list_assets(release_id))
        for asset in expected.values():
            api.verify_asset_bytes(asset)
        _require_draft(api.get_release(release_id), release_id, tag)
        check_assets(expected, api.list_assets(release_id))
        _require_repository_state(api, tag, commit)
        response_unknown = False
        try:
            api.publish_draft(release_id)
        except RequestOutcomeUnknown:
            response_unknown = True
        try:
            _confirm_published(api, release_id, tag, commit, expected)
        except (PublishError, ValueError):
            error = RequestOutcomeUnknown if response_unknown else PublishError
            raise error(f"could not verify publication of GitHub release {release_id}") from None
        return release_id
