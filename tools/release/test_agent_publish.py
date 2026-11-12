import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from agent_manifest import BuildFacts, FileFacts, UploadedAssetFacts
from agent_publish import (
    GithubReleaseApi,
    GithubReleaseRecord,
    PublishError,
    RequestOutcomeUnknown,
    publish_agent,
)


TAG = "agent-v0.1.0"
COMMIT = "a" * 40
RELEASE_ID = 321
API_PATH = "/repos/DashunLiu/Nodomio"
UPLOAD_URL = f"https://uploads.github.com{API_PATH}/releases/321/assets{{?name,label}}"
X64 = "linux-x86_64"
ARM64 = "linux-aarch64"
X64_PACKAGE = f"nodomi-agent-0.1.0-{X64}.tar.gz"
X64_MANIFEST = f"nodomi-agent-0.1.0-{X64}.release.json"
ARM64_PACKAGE = f"nodomi-agent-0.1.0-{ARM64}.tar.gz"
ARM64_MANIFEST = f"nodomi-agent-0.1.0-{ARM64}.release.json"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def draft():
    return GithubReleaseRecord(RELEASE_ID, TAG, True, False, False, None, UPLOAD_URL)


class FakeApi:
    def __init__(self):
        self.release = None
        self.assets = {}
        self.payloads = {}
        self.calls = []
        self.settings = [True, True]
        self.commits = [COMMIT] * 3
        self.lose_patch_response = False
        self.apply_patch = True
        self.change_after_publish = False
        self.change_before_publish = False
        self.published_on_exact_read = False
        self.corrupt_readback = False

    def immutable_enabled(self):
        self.calls.append(("setting",))
        return self.settings.pop(0)

    def tag_commit(self, tag):
        self.calls.append(("tag", tag))
        return self.commits.pop(0)

    def find_releases(self, tag):
        self.calls.append(("find", tag))
        return [self.release] if self.release else []

    def create_draft(self, tag, commit):
        self.calls.append(("create", tag, commit))
        self.release = draft()
        return self.release

    def get_release(self, release_id):
        self.calls.append(("get", release_id))
        if self.published_on_exact_read:
            return replace(self.release, draft=False, published_at="2026-11-11T04:00:00Z")
        return self.release

    def list_assets(self, release_id):
        self.calls.append(("assets", release_id))
        if (self.change_after_publish and not self.release.draft) or (
            self.change_before_publish and len(self.assets) == 4
        ):
            changed = replace(self.assets[X64_PACKAGE], id=900)
            return [changed, *(asset for name, asset in self.assets.items() if name != X64_PACKAGE)]
        return list(self.assets.values())

    def upload_asset(self, release, source, facts):
        self.calls.append(("upload", release.id, facts.name))
        assert release == self.release and release.draft
        assert facts.name not in self.assets
        data = source.read()
        self.payloads[facts.name] = data
        asset = UploadedAssetFacts(500 + len(self.assets), facts.name, len(data), sha256(data))
        self.assets[facts.name] = asset
        return asset

    def publish_draft(self, release_id):
        self.calls.append(("publish", release_id))
        if self.apply_patch:
            self.release = replace(
                self.release, draft=False, immutable=True, published_at="2026-11-11T04:00:00Z"
            )
        if self.lose_patch_response:
            raise RequestOutcomeUnknown("lost response")

    def verify_asset_bytes(self, asset):
        self.calls.append(("verify", asset.id))
        if self.corrupt_readback or sha256(self.payloads[asset.name]) != asset.sha256:
            raise PublishError("release asset readback mismatch")


class PublishAgentTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        compatibility = {
            "wireProtocols": [1], "supervisorProtocols": [1],
            "readConfigFormats": [1], "writeConfigFormat": 1,
            "readQueueFormats": [1], "writeQueueFormat": 1,
            "minKernel": "5.4.0", "libc": "STATIC", "minLibcVersion": None,
        }
        self.builds = []
        self.packages = {}
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for platform, name in [(X64, X64_PACKAGE), (ARM64, ARM64_PACKAGE)]:
            data = f"fictional build: {platform}\n".encode()
            package = work / name
            package.write_bytes(data)
            self.packages[platform] = package
            self.builds.append(BuildFacts(
                TAG, COMMIT, platform, False, compatibility, FileFacts(name, len(data), sha256(data))
            ))

    def publish(self):
        return publish_agent(self.api, self.builds, self.packages)

    def test_invalid_local_inputs_cannot_begin_remote_work(self):
        self.packages[ARM64].write_bytes(b"wrong bytes")
        with self.assertRaises((PublishError, ValueError)):
            self.publish()
        self.assertEqual(self.api.calls, [])

    def test_package_symlink_is_rejected_even_when_target_bytes_match(self):
        path = self.packages[ARM64]
        target = path.with_suffix(".real")
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(PublishError):
            self.publish()
        self.assertEqual(self.api.calls, [])

    def test_inconsistent_platform_builds_cannot_begin_remote_work(self):
        self.builds[1] = replace(self.builds[1], is_security_update=True)
        with self.assertRaises((PublishError, ValueError)):
            self.publish()
        self.assertEqual(self.api.calls, [])

    def test_uploads_programs_then_manifests_bound_to_real_asset_ids(self):
        self.assertEqual(self.publish(), RELEASE_ID)
        mutations = [call for call in self.api.calls if call[0] in {"create", "upload", "publish"}]
        self.assertEqual(mutations[0], ("create", TAG, COMMIT))
        self.assertEqual(
            {call[2] for call in mutations[1:3]}, {X64_PACKAGE, ARM64_PACKAGE}
        )
        self.assertEqual(
            {call[2] for call in mutations[3:5]}, {X64_MANIFEST, ARM64_MANIFEST}
        )
        self.assertEqual(mutations[5:], [("publish", RELEASE_ID)])
        for name, package in [(X64_MANIFEST, X64_PACKAGE), (ARM64_MANIFEST, ARM64_PACKAGE)]:
            manifest = json.loads(self.api.payloads[name])
            self.assertEqual(manifest["custom"]["nodomi"]["github"]["releaseId"], RELEASE_ID)
            self.assertEqual(
                manifest["custom"]["nodomi"]["github"]["assetId"], self.api.assets[package].id
            )
            self.assertEqual(manifest["hashes"]["sha256"], sha256(self.api.payloads[package]))
        self.assertEqual(self.api.calls.count(("setting",)), 2)
        self.assertEqual(self.api.calls[-3:], [("get", RELEASE_ID), ("assets", RELEASE_ID), ("tag", TAG)])
        self.assertEqual(
            [call for call in self.api.calls if call[0] == "verify"],
            [("verify", self.api.assets[name].id) for name in self.api.assets],
        )

    def test_wrong_bytes_from_exact_release_asset_prevent_publication(self):
        self.api.corrupt_readback = True
        with self.assertRaises(PublishError):
            self.publish()
        self.assertNotIn(("publish", RELEASE_ID), self.api.calls)

    def test_reuses_a_matching_draft_and_assets_without_overwrite(self):
        self.publish()
        prior_payloads = dict(self.api.payloads)
        self.api.release = draft()
        self.api.calls.clear()
        self.api.settings = [True, True]
        self.api.commits = [COMMIT] * 3
        self.assertEqual(self.publish(), RELEASE_ID)
        self.assertEqual(self.api.payloads, prior_payloads)
        self.assertFalse(any(call[0] in {"create", "upload"} for call in self.api.calls))

    def test_existing_published_release_or_conflicting_draft_asset_stops(self):
        for release, assets in [
            (replace(draft(), draft=False, published_at="2026-11-11T04:00:00Z"), {}),
            (draft(), {X64_PACKAGE: UploadedAssetFacts(500, X64_PACKAGE, 1, "0" * 64)}),
        ]:
            with self.subTest(release=release, assets=assets):
                self.api = FakeApi()
                self.api.release, self.api.assets = release, assets
                with self.assertRaises((PublishError, ValueError)):
                    self.publish()
                self.assertFalse(any(call[0] in {"create", "upload", "publish"} for call in self.api.calls))

    def test_catalog_draft_published_before_exact_read_cannot_receive_assets(self):
        self.api.release = draft()
        self.api.published_on_exact_read = True
        with self.assertRaises(PublishError):
            self.publish()
        self.assertFalse(any(call[0] in {"create", "upload", "publish"} for call in self.api.calls))

    def test_missing_immutable_policy_or_changed_tag_stops_before_writes(self):
        for settings, commits in [([False], [COMMIT]), ([True], ["b" * 40])]:
            with self.subTest(settings=settings, commits=commits):
                self.api = FakeApi()
                self.api.settings, self.api.commits = settings, commits
                with self.assertRaises((PublishError, ValueError)):
                    self.publish()
                self.assertFalse(any(call[0] in {"create", "upload", "publish"} for call in self.api.calls))

    def test_asset_tag_and_policy_are_rechecked_before_patch(self):
        for case in ("asset", "tag", "policy"):
            with self.subTest(case=case):
                self.api = FakeApi()
                if case == "asset":
                    self.api.change_before_publish = True
                elif case == "tag":
                    self.api.commits[1] = "b" * 40
                else:
                    self.api.settings[1] = False
                with self.assertRaises((PublishError, ValueError)):
                    self.publish()
                self.assertNotIn(("publish", RELEASE_ID), self.api.calls)
                self.assertTrue(self.api.release.draft)

    def test_lost_patch_response_reads_exact_id_without_repeating_mutation(self):
        self.api.lose_patch_response = True
        self.assertEqual(self.publish(), RELEASE_ID)
        self.assertEqual(self.api.calls.count(("publish", RELEASE_ID)), 1)
        self.assertEqual(self.api.calls[-3:], [("get", RELEASE_ID), ("assets", RELEASE_ID), ("tag", TAG)])

    def test_lost_patch_response_with_draft_keeps_outcome_unknown(self):
        self.api.lose_patch_response = True
        self.api.apply_patch = False
        with self.assertRaisesRegex(RequestOutcomeUnknown, str(RELEASE_ID)):
            self.publish()
        self.assertEqual(self.api.calls.count(("publish", RELEASE_ID)), 1)
        self.assertEqual(self.api.calls[-1], ("get", RELEASE_ID))

    def test_published_asset_change_cannot_report_success(self):
        self.api.change_after_publish = True
        with self.assertRaises((PublishError, ValueError)):
            self.publish()
        self.assertEqual(self.api.calls.count(("publish", RELEASE_ID)), 1)


class FakeResponse:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())
        self.headers = headers

    def read(self, limit):
        return self.body.read(limit)

    def getheaders(self):
        return self.headers


class GithubReleaseApiTests(unittest.TestCase):
    def setUp(self):
        self.responses = []
        self.requests = []

        def connect(host, **_kwargs):
            test = self

            class Connection:
                def request(self, method, path, body=None, headers=None):
                    if hasattr(body, "read"):
                        body = body.read()
                    test.requests.append((host, method, path, body, headers))

                def getresponse(self):
                    response = test.responses.pop(0)
                    if isinstance(response, BaseException):
                        raise response
                    return FakeResponse(*response)

                def close(self):
                    pass

            return Connection()

        self.enterContext(patch("http.client.HTTPSConnection", side_effect=connect))
        self.api = GithubReleaseApi("publish-test-token", "settings-test-token")

    def test_settings_token_is_used_only_for_admin_get(self):
        self.responses.extend([(200, {"enabled": True, "enforced_by_owner": False}, []), (200, [], [])])
        self.assertIs(self.api.immutable_enabled(), True)
        self.assertEqual(self.api.find_releases(TAG), [])
        self.assertEqual([item[:3] for item in self.requests], [
            ("api.github.com", "GET", f"{API_PATH}/immutable-releases"),
            ("api.github.com", "GET", f"{API_PATH}/releases?per_page=100&page=1"),
        ])
        self.assertEqual([item[4]["Authorization"] for item in self.requests], [
            "Bearer settings-test-token", "Bearer publish-test-token"
        ])

    def test_successful_reviewed_run_is_bound_to_exact_workflow_repository_and_sha(self):
        run = {
            "id": 42, "head_branch": "main", "head_sha": COMMIT,
            "path": ".github/workflows/agent-build.yml@main",
            "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
            "repository": {"id": 21, "full_name": "DashunLiu/Nodomio"},
            "head_repository": {"id": 21, "full_name": "DashunLiu/Nodomio"},
        }
        self.responses.append((200, run, []))
        self.api.verify_build_run(42, COMMIT)
        self.assertEqual(self.requests[0][:3], ("api.github.com", "GET", f"{API_PATH}/actions/runs/42"))
        for update in (
            {"id": 43}, {"head_branch": "topic"}, {"head_sha": "b" * 40},
            {"path": ".github/workflows/other.yml"}, {"event": "pull_request"},
            {"status": "in_progress"}, {"conclusion": "failure"},
            {"head_repository": {"id": 22, "full_name": "other/Nodomio"}},
        ):
            with self.subTest(update=update), self.assertRaises(PublishError):
                self.responses.append((200, run | update, []))
                self.api.verify_build_run(42, COMMIT)

    def test_exact_asset_readback_verifies_bytes_without_forwarding_credentials(self):
        data = b"archive"
        asset = UploadedAssetFacts(500, X64_PACKAGE, len(data), sha256(data))
        self.responses.extend([
            (302, b"", [("Location", "https://release-assets.githubusercontent.com/asset?sig=fake")]),
            (200, data, [("Content-Length", str(len(data)))]),
        ])
        self.api.verify_asset_bytes(asset)
        self.assertEqual(self.requests[0][:3], ("api.github.com", "GET", f"{API_PATH}/releases/assets/500"))
        self.assertEqual(self.requests[0][4]["Authorization"], "Bearer publish-test-token")
        self.assertEqual(self.requests[0][4]["Accept"], "application/octet-stream")
        self.assertEqual(self.requests[1][:3], ("release-assets.githubusercontent.com", "GET", "/asset?sig=fake"))
        self.assertNotIn("Authorization", self.requests[1][4])

    def test_asset_readback_rejects_wrong_bytes_and_untrusted_redirect(self):
        asset = UploadedAssetFacts(500, X64_PACKAGE, 3, sha256(b"abc"))
        for status, body, headers in [
            (200, b"abd", []),
            (200, b"abcx", []),
            (200, b"ab", []),
            (200, b"abc", [("Content-Encoding", "gzip")]),
            (302, b"", [("Location", "https://" + "release-assets.githubusercontent.com@other.invalid/a")]),
            (302, b"", [("Location", "https://release-assets.githubusercontent.com:444/a")]),
            (302, b"", [("Location", "http://objects.githubusercontent.com/a")]),
        ]:
            with self.subTest(status=status, headers=headers), self.assertRaises(PublishError):
                self.requests.clear()
                self.responses.append((status, body, headers))
                self.api.verify_asset_bytes(asset)
                self.assertEqual(len(self.requests), 1)

    def test_catalog_numeric_pagination_still_uses_fixed_named_api_path(self):
        self.responses.extend([
            (200, [{"id": 320, "tag_name": "system-v1.0.0"}],
             [("Link", '<https://api.github.com/repositories/987/releases?per_page=100&page=2>; rel="next"')]),
            (200, [{"id": RELEASE_ID, "tag_name": TAG, "draft": True,
                    "prerelease": False, "published_at": None, "immutable": False,
                    "upload_url": UPLOAD_URL}], []),
        ])
        self.assertEqual(self.api.find_releases(TAG), [draft()])
        self.assertEqual(self.requests[1][:3], ("api.github.com", "GET", f"{API_PATH}/releases?per_page=100&page=2"))

    def test_annotated_tag_is_peeled_by_exact_object_id(self):
        annotation = "b" * 40
        self.responses.extend([
            (200, {"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": annotation}}, []),
            (200, {"sha": annotation, "object": {"type": "commit", "sha": COMMIT}}, []),
        ])
        self.assertEqual(self.api.tag_commit(TAG), COMMIT)
        self.assertEqual([item[2] for item in self.requests], [
            f"{API_PATH}/git/ref/tags/{TAG}", f"{API_PATH}/git/tags/{annotation}"
        ])

    def test_create_draft_keeps_the_repositories_latest_release_independent(self):
        self.responses.append((201, {
            "id": RELEASE_ID, "tag_name": TAG, "draft": True, "prerelease": False,
            "immutable": False, "published_at": None, "upload_url": UPLOAD_URL,
        }, []))
        self.assertEqual(self.api.create_draft(TAG, COMMIT), draft())
        self.assertEqual(self.requests[0][:3], ("api.github.com", "POST", f"{API_PATH}/releases"))
        self.assertEqual(json.loads(self.requests[0][3]), {
            "tag_name": TAG, "target_commitish": COMMIT, "draft": True,
            "prerelease": False, "make_latest": "false",
        })

    def test_successful_post_with_unusable_response_has_unknown_outcome(self):
        from io import BytesIO

        for response in [b"{", b"x" * (2 * 1024 * 1024 + 1), {"id": RELEASE_ID}]:
            with self.subTest(response_type=type(response), size=len(response)):
                self.requests.clear()
                self.responses.append((201, response, []))
                with self.assertRaisesRegex(RequestOutcomeUnknown, TAG):
                    self.api.create_draft(TAG, COMMIT)
                self.assertEqual(len(self.requests), 1)

        self.requests.clear()
        data = b"package"
        facts = FileFacts(X64_PACKAGE, len(data), sha256(data))
        self.responses.append((201, {"id": 500, "name": X64_PACKAGE,
                                     "size": len(data), "state": "uploaded", "digest": None}, []))
        with self.assertRaisesRegex(RequestOutcomeUnknown, str(RELEASE_ID)):
            self.api.upload_asset(draft(), BytesIO(data), facts)
        self.assertEqual(len(self.requests), 1)

    def test_upload_url_and_write_redirects_never_forward_credentials(self):
        from io import BytesIO

        data = b"package"
        facts = FileFacts(X64_PACKAGE, len(data), sha256(data))
        with self.assertRaises(PublishError):
            self.api.upload_asset(replace(draft(), upload_url="https://example.invalid/"), BytesIO(data), facts)
        self.assertEqual(self.requests, [])
        self.responses.append((302, {}, [("Location", "https://example.invalid/")]))
        with self.assertRaises(PublishError):
            self.api.upload_asset(draft(), BytesIO(data), facts)
        self.assertEqual(len(self.requests), 1)
        host, method, path, body, headers = self.requests[0]
        self.assertEqual((host, method, path, body), (
            "uploads.github.com", "POST", f"{API_PATH}/releases/321/assets?name={X64_PACKAGE}", data
        ))
        self.assertEqual(headers["Content-Length"], str(len(data)))

    def test_patch_transport_failure_is_unknown_and_has_no_retry(self):
        self.responses.append(ConnectionError("arbitrary sensitive transport detail"))
        with self.assertRaises(RequestOutcomeUnknown) as context:
            self.api.publish_draft(RELEASE_ID)
        self.assertNotIn("sensitive", str(context.exception))
        self.assertIn(str(RELEASE_ID), str(context.exception))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0][:3], ("api.github.com", "PATCH", f"{API_PATH}/releases/321"))
        self.assertEqual(json.loads(self.requests[0][3]), {"draft": False, "make_latest": "false"})
