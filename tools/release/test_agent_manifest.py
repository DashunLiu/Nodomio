import unittest
from dataclasses import replace

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
    package_name,
    version_for_tag,
)


TAG = "agent-v0.1.1"
COMMIT = "1234567890abcdef1234567890abcdef12345678"
HASH = "a" * 64
X86 = "linux-x86_64"
ARM = "linux-aarch64"
SAFE_INT = 9_007_199_254_740_991


def build_for(platform=X86, *, tag=TAG):
    package = FileFacts(f"nodomi-agent-{tag.removeprefix('agent-v')}-{platform}.tar.gz", 12345, HASH)
    return BuildFacts(
        tag=tag,
        commit=COMMIT,
        platform=platform,
        is_security_update=True,
        compatibility={
            "wireProtocols": [1],
            "supervisorProtocols": [1],
            "readConfigFormats": [1, 2],
            "writeConfigFormat": 1,
            "readQueueFormats": [1, 2],
            "writeQueueFormat": 1,
            "minKernel": "5.10.0",
            "libc": "STATIC",
            "minLibcVersion": None,
        },
        package=package,
    )


def uploaded(build, asset_id=456):
    return UploadedAssetFacts(asset_id, build.package.name, build.package.length, build.package.sha256)


class AgentManifestTests(unittest.TestCase):
    def test_rerun_keeps_business_identity_and_sequence(self):
        self.assertEqual(REPOSITORY, "DashunLiu/Nodomio")
        self.assertEqual(set(PLATFORMS), {X86, ARM})
        release = GithubDraftFacts(123, TAG, COMMIT)
        build = build_for()
        manifest = make_manifest(build, release, uploaded(build))
        self.assertEqual(manifest, make_manifest(build, release, uploaded(build)))
        self.assertEqual(manifest["length"], 12345)
        self.assertEqual(manifest["hashes"], {"sha256": HASH})
        self.assertEqual(
            manifest["custom"]["nodomi"],
            {
                "schemaVersion": 1,
                "component": "AGENT",
                "releaseId": "9ff55f9f-d008-5d06-a43e-f9c98a2de598",
                "sequence": 100002,
                "version": "0.1.1",
                "channel": "STABLE",
                "platform": X86,
                "isSecurityUpdate": True,
                "compatibility": build.compatibility,
                "github": {
                    "owner": "DashunLiu",
                    "repo": "Nodomio",
                    "releaseId": 123,
                    "assetId": 456,
                    "assetName": "nodomi-agent-0.1.1-linux-x86_64.tar.gz",
                },
                "status": "ACTIVE",
            },
        )
        arm = build_for(ARM)
        arm_target = make_manifest(arm, release, uploaded(arm, 457))["custom"]["nodomi"]
        for field in ("releaseId", "version", "sequence", "isSecurityUpdate"):
            self.assertEqual(arm_target[field], manifest["custom"]["nodomi"][field])
        self.assertEqual(arm_target["github"]["assetId"], 457)
        self.assertEqual(arm_target["platform"], ARM)
        different_release = make_manifest(build, replace(release, id=124), uploaded(build))
        self.assertNotEqual(
            different_release["custom"]["nodomi"]["releaseId"], arm_target["releaseId"]
        )
        self.assertEqual(different_release["custom"]["nodomi"]["sequence"], arm_target["sequence"])

    def test_tag_range_and_canonical_filenames(self):
        for tag, sequence in (
            ("agent-v0.0.0", 1),
            ("agent-v0.0.99999", 100000),
            ("agent-v0.1.0", 100001),
            ("agent-v1.0.0", 10000000001),
            ("agent-v99999.99999.99999", 1000000000000000),
        ):
            with self.subTest(tag=tag):
                version = tag.removeprefix("agent-v")
                build = build_for(tag=tag)
                release = GithubDraftFacts(SAFE_INT, tag, COMMIT)
                record = make_manifest(build, release, uploaded(build, SAFE_INT))["custom"]["nodomi"]
                self.assertEqual(version_for_tag(tag), version)
                self.assertEqual(record["sequence"], sequence)
                self.assertEqual(package_name(tag, ARM), f"nodomi-agent-{version}-{ARM}.tar.gz")
                self.assertEqual(manifest_name(tag, ARM), f"nodomi-agent-{version}-{ARM}.release.json")
        for tag in (
            "v0.1.1", "backend-v0.1.1", "agent-v0.01.1", "agent-v+0.1.1",
            "agent-v0.1", "agent-v0.1.1.0", "agent-v0.1.1-rc.1", "agent-v0.1.1+build",
            "agent-v100000.1.1", "agent-v0.100000.1", "agent-v0.1.100000",
            "agent-v0.1.1\n", "agent-v٠.1.1", None,
        ):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                version_for_tag(tag)
        for name in (package_name, manifest_name):
            with self.assertRaises(ValueError):
                name(TAG, "linux-riscv64")

    def test_actual_ids_digests_and_both_platforms_must_agree(self):
        build = build_for()
        arm = build_for(ARM)
        release = GithubDraftFacts(123, TAG, COMMIT)
        asset = uploaded(build)
        check_builds([build, replace(arm, compatibility={**arm.compatibility, "minKernel": "5.4.0"})])

        for candidate in (
            [build],
            [build, build],
            [build, arm, arm],
            [build, replace(arm, is_security_update=False)],
            [build, replace(arm, commit="f" * 40)],
            [build, build_for(ARM, tag="agent-v0.1.2")],
            [build, replace(arm, package=build.package)],
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                check_builds(candidate)

        for candidate in (
            replace(release, id=0),
            replace(release, id=True),
            replace(release, id=SAFE_INT + 1),
            replace(release, tag="agent-v0.1.2"),
            replace(release, commit="f" * 40),
            replace(release, commit="main"),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                make_manifest(build, candidate, asset)

        for candidate in (
            replace(asset, id=0),
            replace(asset, id=True),
            replace(asset, id=SAFE_INT + 1),
            replace(asset, name=arm.package.name),
            replace(asset, length=asset.length + 1),
            replace(asset, sha256="b" * 64),
            replace(asset, sha256="A" * 64),
            replace(asset, sha256="sha256:" + HASH),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                make_manifest(build, release, candidate)

        for package in (
            replace(build.package, name="../artifact.tar.gz"),
            replace(build.package, length=0),
            replace(build.package, length=512 * 1024 * 1024 + 1),
            replace(build.package, length=True),
            replace(build.package, sha256="b" * 63),
        ):
            with self.subTest(package=package), self.assertRaises(ValueError):
                candidate = replace(build, package=package)
                make_manifest(candidate, release, uploaded(candidate))

        for candidate in (
            replace(build, platform="linux-riscv64"),
            replace(build, is_security_update=1),
            replace(build, commit="0" * 39),
            replace(build, commit="F" * 40),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                make_manifest(candidate, replace(release, commit=candidate.commit), asset)

    def test_all_assets_before_immutable_publish(self):
        build = build_for()
        arm = build_for(ARM)
        assets = [
            uploaded(build, 456),
            uploaded(arm, 457),
            UploadedAssetFacts(458, "nodomi-agent-0.1.1-linux-x86_64.release.json", 573, "b" * 64),
            UploadedAssetFacts(459, "nodomi-agent-0.1.1-linux-aarch64.release.json", 575, "c" * 64),
        ]
        expected = {asset.name: asset for asset in assets}
        check_assets(expected, list(reversed(assets)))
        for observed in (
            assets[:-1],
            assets + [UploadedAssetFacts(460, "unexpected.txt", 1, HASH)],
            assets[:-1] + [replace(assets[-1], id=assets[0].id)],
            assets[:-1] + [replace(assets[-1], name=assets[0].name)],
            assets[:-1] + [replace(assets[-1], id=460)],
            assets[:-1] + [replace(assets[-1], length=574)],
            assets[:-1] + [replace(assets[-1], sha256=HASH)],
        ):
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                check_assets(expected, observed)

        malformed = replace(assets[-1], id=True)
        with self.assertRaises(ValueError):
            check_assets({**expected, malformed.name: malformed}, assets[:-1] + [malformed])
        with self.assertRaises(ValueError):
            check_assets({"wrong-name": assets[0]}, [assets[0]])

    def test_compatibility_matches_agent_parser_and_owns_its_output(self):
        build = build_for()
        release = GithubDraftFacts(123, TAG, COMMIT)
        abi = {
            **build.compatibility,
            "wireProtocols": [1, 2],
            "libc": "MUSL",
            "minLibcVersion": "1.2.3",
        }
        dynamic = replace(build, compatibility=abi)
        emitted = make_manifest(dynamic, release, uploaded(dynamic))["custom"]["nodomi"]["compatibility"]
        self.assertEqual(emitted, abi)
        abi["wireProtocols"].append(3)
        self.assertEqual(emitted["wireProtocols"], [1, 2])

        for changes in (
            {"extra": True},
            {"wireProtocols": [2]},
            {"wireProtocols": [True]},
            {"supervisorProtocols": []},
            {"supervisorProtocols": [1, 1]},
            {"readConfigFormats": list(range(1, 18))},
            {"readQueueFormats": [SAFE_INT + 1]},
            {"writeConfigFormat": 3},
            {"writeQueueFormat": True},
            {"minKernel": "5.010.0"},
            {"minKernel": "5.10"},
            {"minKernel": "18446744073709551616.0.0"},
            {"libc": "unknown"},
            {"libc": "GLIBC"},
            {"libc": "MUSL", "minLibcVersion": "1.02.3"},
            {"libc": "STATIC", "minLibcVersion": "1.2.3"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                candidate = replace(build, compatibility={**build.compatibility, **changes})
                make_manifest(candidate, release, uploaded(candidate))

        missing = {key: value for key, value in build.compatibility.items() if key != "minLibcVersion"}
        with self.assertRaises(ValueError):
            make_manifest(replace(build, compatibility=missing), release, uploaded(build))


if __name__ == "__main__":
    unittest.main()
