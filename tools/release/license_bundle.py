#!/usr/bin/env python3
"""Produce bounded legal materials for the pinned, native static-musl release.

Run after the release build. This inventory deliberately includes the active
normal Cargo graph (including macro helpers) and installed toolchain materials;
it is not a claim that every inventoried component contributes linked bytes.
No network requests, extraction, or dependencies outside the Python stdlib.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

MAX_BUNDLE = 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_DOCUMENT = 512 * 1024
TARGETS = {"aarch64-unknown-linux-musl": "aarch64", "x86_64-unknown-linux-musl": "x86_64"}
LEGAL_NAME = re.compile(r"(?:licen[cs]e|copying|notice|copyright|unlicense|authors)(?:[._-].*)?", re.I)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


# Exact upstream legal documents for the pinned Rust 1.91.1 static runtime.
# Source: https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT?h=v1.2.3
# SHA-256: f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af
MUSL_NOTICE = b'musl as a whole is licensed under the following standard MIT license:\n\n----------------------------------------------------------------------\nCopyright \xc2\xa9 2005-2020 Rich Felker, et al.\n\nPermission is hereby granted, free of charge, to any person obtaining\na copy of this software and associated documentation files (the\n"Software"), to deal in the Software without restriction, including\nwithout limitation the rights to use, copy, modify, merge, publish,\ndistribute, sublicense, and/or sell copies of the Software, and to\npermit persons to whom the Software is furnished to do so, subject to\nthe following conditions:\n\nThe above copyright notice and this permission notice shall be\nincluded in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,\nEXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\nMERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\nIN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY\nCLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,\nTORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE\nSOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n----------------------------------------------------------------------\n\nAuthors/contributors include:\n\nA. Wilcox\nAda Worcester\nAlex Dowad\nAlex Suykov\nAlexander Monakov\nAndre McCurdy\nAndrew Kelley\nAnthony G. Basile\nAric Belsito\nArvid Picciani\nBartosz Brachaczek\nBenjamin Peterson\nBobby Bingham\nBoris Brezillon\nBrent Cook\nChris Spiegel\nCl\xc3\xa9ment Vasseur\nDaniel Micay\nDaniel Sabogal\nDaurnimator\nDavid Carlier\nDavid Edelsohn\nDenys Vlasenko\nDmitry Ivanov\nDmitry V. Levin\nDrew DeVault\nEmil Renner Berthing\nFangrui Song\nFelix Fietkau\nFelix Janda\nGianluca Anzolin\nHauke Mehrtens\nHe X\nHiltjo Posthuma\nIsaac Dunham\nJaydeep Patil\nJens Gustedt\nJeremy Huntwork\nJo-Philipp Wich\nJoakim Sindholt\nJohn Spencer\nJulien Ramseier\nJustin Cormack\nKaarle Ritvanen\nKhem Raj\nKylie McClain\nLeah Neukirchen\nLuca Barbato\nLuka Perkov\nM Farkas-Dyck (Strake)\nMahesh Bodapati\nMarkus Wichmann\nMasanori Ogino\nMichael Clark\nMichael Forney\nMikhail Kremnyov\nNatanael Copa\nNicholas J. Kain\norc\nPascal Cuoq\nPatrick Oppenlander\nPetr Hosek\nPetr Skocik\nPierre Carrier\nReini Urban\nRich Felker\nRichard Pennington\nRyan Fairfax\nSamuel Holland\nSegev Finer\nShiz\nsin\nSolar Designer\nStefan Kristiansson\nStefan O\'Rear\nSzabolcs Nagy\nTimo Ter\xc3\xa4s\nTrutz Behn\nValentin Ochs\nWill Dietz\nWilliam Haddon\nWilliam Pitcock\n\nPortions of this software are derived from third-party works licensed\nunder terms compatible with the above MIT license:\n\nThe TRE regular expression implementation (src/regex/reg* and\nsrc/regex/tre*) is Copyright \xc2\xa9 2001-2008 Ville Laurikari and licensed\nunder a 2-clause BSD license (license text in the source files). The\nincluded version has been heavily modified by Rich Felker in 2012, in\nthe interests of size, simplicity, and namespace cleanliness.\n\nMuch of the math library code (src/math/* and src/complex/*) is\nCopyright \xc2\xa9 1993,2004 Sun Microsystems or\nCopyright \xc2\xa9 2003-2011 David Schultz or\nCopyright \xc2\xa9 2003-2009 Steven G. Kargl or\nCopyright \xc2\xa9 2003-2009 Bruce D. Evans or\nCopyright \xc2\xa9 2008 Stephen L. Moshier or\nCopyright \xc2\xa9 2017-2018 Arm Limited\nand labelled as such in comments in the individual source files. All\nhave been licensed under extremely permissive terms.\n\nThe ARM memcpy code (src/string/arm/memcpy.S) is Copyright \xc2\xa9 2008\nThe Android Open Source Project and is licensed under a two-clause BSD\nlicense. It was taken from Bionic libc, used on Android.\n\nThe AArch64 memcpy and memset code (src/string/aarch64/*) are\nCopyright \xc2\xa9 1999-2019, Arm Limited.\n\nThe implementation of DES for crypt (src/crypt/crypt_des.c) is\nCopyright \xc2\xa9 1994 David Burren. It is licensed under a BSD license.\n\nThe implementation of blowfish crypt (src/crypt/crypt_blowfish.c) was\noriginally written by Solar Designer and placed into the public\ndomain. The code also comes with a fallback permissive license for use\nin jurisdictions that may not recognize the public domain.\n\nThe smoothsort implementation (src/stdlib/qsort.c) is Copyright \xc2\xa9 2011\nValentin Ochs and is licensed under an MIT-style license.\n\nThe x86_64 port was written by Nicholas J. Kain and is licensed under\nthe standard MIT terms.\n\nThe mips and microblaze ports were originally written by Richard\nPennington for use in the ellcc project. The original code was adapted\nby Rich Felker for build system and code conventions during upstream\nintegration. It is licensed under the standard MIT terms.\n\nThe mips64 port was contributed by Imagination Technologies and is\nlicensed under the standard MIT terms.\n\nThe powerpc port was also originally written by Richard Pennington,\nand later supplemented and integrated by John Spencer. It is licensed\nunder the standard MIT terms.\n\nAll other files which have no copyright comments are original works\nproduced specifically for use as part of this library, written either\nby Rich Felker, the main author of the library, or by one or more\ncontibutors listed above. Details on authorship of individual files\ncan be found in the git version control history of the project. The\nomission of copyright and license comments in each file is in the\ninterest of source tree size.\n\nIn addition, permission is hereby granted for all public header files\n(include/* and arch/*/bits/*) and crt files intended to be linked into\napplications (crt/*, ldso/dlstart.c, and arch/*/crt_arch.h) to omit\nthe copyright notice and permission notice otherwise required by the\nlicense, and to use these files without any requirement of\nattribution. These files include substantial contributions from:\n\nBobby Bingham\nJohn Spencer\nNicholas J. Kain\nRich Felker\nRichard Pennington\nStefan Kristiansson\nSzabolcs Nagy\n\nall of whom have explicitly granted such permission.\n\nThis file previously contained text expressing a belief that most of\nthe files covered by the above exception were sufficiently trivial not\nto be subject to copyright, resulting in confusion over whether it\nnegated the permissions granted in the license. In the spirit of\npermissive licensing, and of not having licensing issues being an\nobstacle to adoption, that text has been removed.\n'
# Source: https://raw.githubusercontent.com/rust-lang/rust/1.91.1/library/compiler-builtins/LICENSE.txt
# SHA-256: ab6eec6caf0fa5775e411c7a8bc6a45c4ef2956b0980b157ab74fc5cd62a928b
COMPILER_BUILTINS_NOTICE = b'The compiler-builtins crate is available for use under both the MIT license\nand the Apache-2.0 license with the LLVM exception (MIT AND Apache-2.0 WITH\nLLVM-exception).\n\nThe libm crate is available for use under the MIT license.\n\nAs a contributor, you agree that your code may be used under any of the\nfollowing: the MIT license, the Apache-2.0 license, or the Apache-2.0 license\nwith the LLVM exception. In other words, original (non-derivative) work is\nlicensed under MIT OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception. This is\nthe default license for all other source in this repository.\n\nText of the relevant licenses is provided below:\n\n------------------------------------------------------------------------------\nMIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the "Software"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n------------------------------------------------------------------------------\n                                 Apache License\n                           Version 2.0, January 2004\n                        http://www.apache.org/licenses/\n\n    TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n\n    1. Definitions.\n\n      "License" shall mean the terms and conditions for use, reproduction,\n      and distribution as defined by Sections 1 through 9 of this document.\n\n      "Licensor" shall mean the copyright owner or entity authorized by\n      the copyright owner that is granting the License.\n\n      "Legal Entity" shall mean the union of the acting entity and all\n      other entities that control, are controlled by, or are under common\n      control with that entity. For the purposes of this definition,\n      "control" means (i) the power, direct or indirect, to cause the\n      direction or management of such entity, whether by contract or\n      otherwise, or (ii) ownership of fifty percent (50%) or more of the\n      outstanding shares, or (iii) beneficial ownership of such entity.\n\n      "You" (or "Your") shall mean an individual or Legal Entity\n      exercising permissions granted by this License.\n\n      "Source" form shall mean the preferred form for making modifications,\n      including but not limited to software source code, documentation\n      source, and configuration files.\n\n      "Object" form shall mean any form resulting from mechanical\n      transformation or translation of a Source form, including but\n      not limited to compiled object code, generated documentation,\n      and conversions to other media types.\n\n      "Work" shall mean the work of authorship, whether in Source or\n      Object form, made available under the License, as indicated by a\n      copyright notice that is included in or attached to the work\n      (an example is provided in the Appendix below).\n\n      "Derivative Works" shall mean any work, whether in Source or Object\n      form, that is based on (or derived from) the Work and for which the\n      editorial revisions, annotations, elaborations, or other modifications\n      represent, as a whole, an original work of authorship. For the purposes\n      of this License, Derivative Works shall not include works that remain\n      separable from, or merely link (or bind by name) to the interfaces of,\n      the Work and Derivative Works thereof.\n\n      "Contribution" shall mean any work of authorship, including\n      the original version of the Work and any modifications or additions\n      to that Work or Derivative Works thereof, that is intentionally\n      submitted to Licensor for inclusion in the Work by the copyright owner\n      or by an individual or Legal Entity authorized to submit on behalf of\n      the copyright owner. For the purposes of this definition, "submitted"\n      means any form of electronic, verbal, or written communication sent\n      to the Licensor or its representatives, including but not limited to\n      communication on electronic mailing lists, source code control systems,\n      and issue tracking systems that are managed by, or on behalf of, the\n      Licensor for the purpose of discussing and improving the Work, but\n      excluding communication that is conspicuously marked or otherwise\n      designated in writing by the copyright owner as "Not a Contribution."\n\n      "Contributor" shall mean Licensor and any individual or Legal Entity\n      on behalf of whom a Contribution has been received by Licensor and\n      subsequently incorporated within the Work.\n\n    2. Grant of Copyright License. Subject to the terms and conditions of\n      this License, each Contributor hereby grants to You a perpetual,\n      worldwide, non-exclusive, no-charge, royalty-free, irrevocable\n      copyright license to reproduce, prepare Derivative Works of,\n      publicly display, publicly perform, sublicense, and distribute the\n      Work and such Derivative Works in Source or Object form.\n\n    3. Grant of Patent License. Subject to the terms and conditions of\n      this License, each Contributor hereby grants to You a perpetual,\n      worldwide, non-exclusive, no-charge, royalty-free, irrevocable\n      (except as stated in this section) patent license to make, have made,\n      use, offer to sell, sell, import, and otherwise transfer the Work,\n      where such license applies only to those patent claims licensable\n      by such Contributor that are necessarily infringed by their\n      Contribution(s) alone or by combination of their Contribution(s)\n      with the Work to which such Contribution(s) was submitted. If You\n      institute patent litigation against any entity (including a\n      cross-claim or counterclaim in a lawsuit) alleging that the Work\n      or a Contribution incorporated within the Work constitutes direct\n      or contributory patent infringement, then any patent licenses\n      granted to You under this License for that Work shall terminate\n      as of the date such litigation is filed.\n\n    4. Redistribution. You may reproduce and distribute copies of the\n      Work or Derivative Works thereof in any medium, with or without\n      modifications, and in Source or Object form, provided that You\n      meet the following conditions:\n\n      (a) You must give any other recipients of the Work or\n          Derivative Works a copy of this License; and\n\n      (b) You must cause any modified files to carry prominent notices\n          stating that You changed the files; and\n\n      (c) You must retain, in the Source form of any Derivative Works\n          that You distribute, all copyright, patent, trademark, and\n          attribution notices from the Source form of the Work,\n          excluding those notices that do not pertain to any part of\n          the Derivative Works; and\n\n      (d) If the Work includes a "NOTICE" text file as part of its\n          distribution, then any Derivative Works that You distribute must\n          include a readable copy of the attribution notices contained\n          within such NOTICE file, excluding those notices that do not\n          pertain to any part of the Derivative Works, in at least one\n          of the following places: within a NOTICE text file distributed\n          as part of the Derivative Works; within the Source form or\n          documentation, if provided along with the Derivative Works; or,\n          within a display generated by the Derivative Works, if and\n          wherever such third-party notices normally appear. The contents\n          of the NOTICE file are for informational purposes only and\n          do not modify the License. You may add Your own attribution\n          notices within Derivative Works that You distribute, alongside\n          or as an addendum to the NOTICE text from the Work, provided\n          that such additional attribution notices cannot be construed\n          as modifying the License.\n\n      You may add Your own copyright statement to Your modifications and\n      may provide additional or different license terms and conditions\n      for use, reproduction, or distribution of Your modifications, or\n      for any such Derivative Works as a whole, provided Your use,\n      reproduction, and distribution of the Work otherwise complies with\n      the conditions stated in this License.\n\n    5. Submission of Contributions. Unless You explicitly state otherwise,\n      any Contribution intentionally submitted for inclusion in the Work\n      by You to the Licensor shall be under the terms and conditions of\n      this License, without any additional terms or conditions.\n      Notwithstanding the above, nothing herein shall supersede or modify\n      the terms of any separate license agreement you may have executed\n      with Licensor regarding such Contributions.\n\n    6. Trademarks. This License does not grant permission to use the trade\n      names, trademarks, service marks, or product names of the Licensor,\n      except as required for reasonable and customary use in describing the\n      origin of the Work and reproducing the content of the NOTICE file.\n\n    7. Disclaimer of Warranty. Unless required by applicable law or\n      agreed to in writing, Licensor provides the Work (and each\n      Contributor provides its Contributions) on an "AS IS" BASIS,\n      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or\n      implied, including, without limitation, any warranties or conditions\n      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A\n      PARTICULAR PURPOSE. You are solely responsible for determining the\n      appropriateness of using or redistributing the Work and assume any\n      risks associated with Your exercise of permissions under this License.\n\n    8. Limitation of Liability. In no event and under no legal theory,\n      whether in tort (including negligence), contract, or otherwise,\n      unless required by applicable law (such as deliberate and grossly\n      negligent acts) or agreed to in writing, shall any Contributor be\n      liable to You for damages, including any direct, indirect, special,\n      incidental, or consequential damages of any character arising as a\n      result of this License or out of the use or inability to use the\n      Work (including but not limited to damages for loss of goodwill,\n      work stoppage, computer failure or malfunction, or any and all\n      other commercial damages or losses), even if such Contributor\n      has been advised of the possibility of such damages.\n\n    9. Accepting Warranty or Additional Liability. While redistributing\n      the Work or Derivative Works thereof, You may choose to offer,\n      and charge a fee for, acceptance of support, warranty, indemnity,\n      or other liability obligations and/or rights consistent with this\n      License. However, in accepting such obligations, You may act only\n      on Your own behalf and on Your sole responsibility, not on behalf\n      of any other Contributor, and only if You agree to indemnify,\n      defend, and hold each Contributor harmless for any liability\n      incurred by, or claims asserted against, such Contributor by reason\n      of your accepting any such warranty or additional liability.\n\n    END OF TERMS AND CONDITIONS\n\n    APPENDIX: How to apply the Apache License to your work.\n\n      To apply the Apache License to your work, attach the following\n      boilerplate notice, with the fields enclosed by brackets "[]"\n      replaced with your own identifying information. (Don\'t include\n      the brackets!)  The text should be enclosed in the appropriate\n      comment syntax for the file format. We also recommend that a\n      file or class name and description of purpose be included on the\n      same "printed page" as the copyright notice for easier\n      identification within third-party archives.\n\n    Licensed under the Apache License, Version 2.0 (the "License");\n    you may not use this file except in compliance with the License.\n    You may obtain a copy of the License at\n\n       http://www.apache.org/licenses/LICENSE-2.0\n\n    Unless required by applicable law or agreed to in writing, software\n    distributed under the License is distributed on an "AS IS" BASIS,\n    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n    See the License for the specific language governing permissions and\n    limitations under the License.\n\n\n---- LLVM Exceptions to the Apache 2.0 License ----\n\nAs an exception, if, as a result of your compiling your source code, portions\nof this Software are embedded into an Object form of such source code, you\nmay redistribute such embedded portions in such Object form without complying\nwith the conditions of Sections 4(a), 4(b) and 4(d) of the License.\n\nIn addition, if you combine or link compiled forms of this Software with\nsoftware that is licensed under the GPLv2 ("Combined Software") and if a\ncourt of competent jurisdiction determines that the patent provision (Section\n3), the indemnity provision (Section 9) or other Section of the License\nconflicts with the conditions of the GPLv2, you may retroactively and\nprospectively choose to deem waived or otherwise exclude such Section(s) of\nthe License, but only in their entirety and only with respect to the Combined\nSoftware.\n------------------------------------------------------------------------------\n\nPortions of this software are derived from third-party works licensed under\nterms compatible with the above Apache-2.0 WITH LLVM-exception AND MIT\nlicense:\n\n* compiler-builtins is derived from LLVM\'s compiler-rt (https://llvm.org/).\n  Work derived from compiler-rt prior to 2019-01-19 is usable under the MIT\n  license, with the following copyright:\n\n      Copyright (c) 2009-2016 by the contributors listed in CREDITS.TXT\n\n  The relevant CREDITS.TXT is located at\n  https://github.com/llvm/llvm-project/blob/main/compiler-rt/CREDITS.TXT.\n\n* Work derived from compiler-rt after 2019-01-19 is usable under the\n  Apache-2.0 license with the LLVM exception.\n\n* The bundled `math` module is from the libm crate, usable under the MIT\n  license. For further details and copyrights, see see libm/LICENSE.txt at\n  https://github.com/rust-lang/compiler-builtins.\n\nAdditionally, some source files may contain comments with specific copyrights\nor licenses.\n'


def run(args: list[str], limit: int = 32 * 1024 * 1024) -> str:
    # A file, rather than PIPE capture, avoids retaining unbounded subprocess output.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(args, stdout=output, stderr=errors, timeout=180,
                                env={**os.environ, "CARGO_TERM_COLOR": "never"})
        if result.returncode:
            raise ValueError(f"required command failed: {args[0]} {args[1]}")
        output.seek(0)
        data = output.read(limit + 1)
        if len(data) > limit:
            raise ValueError("command output exceeds bound")
        return data.decode("utf-8", errors="strict")


def checked_text(data: bytes, label: str) -> bytes:
    if not data or len(data) > MAX_DOCUMENT or b"\x00" in data:
        raise ValueError(f"invalid or oversized legal text: {label}")
    data.decode("utf-8", errors="strict")
    return data


def read_document(path: Path, label: str) -> bytes:
    with path.open("rb") as stream:
        return checked_text(stream.read(MAX_DOCUMENT + 1), label)


def selected_packages(repo: Path, target: str) -> list[dict]:
    manifest = repo / "agent/Cargo.toml"
    common = ["--manifest-path", str(manifest), "--locked", "--offline"]
    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", *common,
                               "--filter-platform", target]))
    tree = run(["cargo", "tree", *common, "--target", target, "--edges", "normal",
                "--prefix", "none", "--format", "{p}"])
    selected = set()
    for line in tree.splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_-]+) v([^ ]+)(?: .*|)", line)
        if not match:
            raise ValueError("unrecognized Cargo graph entry")
        selected.add(match.groups())
    lock = tomllib.loads((repo / "agent/Cargo.lock").read_text())
    locked = {(p["name"], p["version"]): p for p in lock["package"] if "source" in p}
    root_id = metadata["resolve"]["root"]
    result = []
    for pair in sorted(selected):
        matches = [p for p in metadata["packages"] if (p["name"], p["version"]) == pair]
        if len(matches) != 1:
            raise ValueError("ambiguous Cargo package identity")
        package = matches[0]
        if package["id"] == root_id:
            continue
        entry = locked.get(pair, {})
        checksum = entry.get("checksum", "")
        if package["source"] != REGISTRY or entry.get("source") != REGISTRY or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("unsupported or unchecked Cargo source")
        result.append({"name": pair[0], "version": pair[1], "checksum": checksum,
                       "license": package.get("license") or "see bundled license file"})
    if not result:
        raise ValueError("empty dependency inventory")
    return result


def archive_documents(package: dict, cargo_home: Path) -> list[tuple[str, bytes]]:
    prefix = f'{package["name"]}-{package["version"]}'
    candidates = sorted((cargo_home / "registry/cache").glob(f"*/{prefix}.crate"))
    valid = []
    for path in candidates:
        if path.stat().st_size > MAX_ARCHIVE:
            raise ValueError("crate archive exceeds bound")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest == package["checksum"]:
            valid.append(path)
    if not valid:
        raise ValueError(f"missing checksum-verified crate archive: {prefix}")
    documents = []
    seen = set()
    verified_manifest = False
    with tarfile.open(valid[0], mode="r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= 30000 or member.offset_data + member.size > 512 * 1024 * 1024:
                raise ValueError("too many crate members")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != prefix:
                raise ValueError("invalid crate member path")
            relative = str(PurePosixPath(*path.parts[1:]))
            if relative == "Cargo.toml":
                if verified_manifest or not member.isfile() or member.size > MAX_DOCUMENT:
                    raise ValueError("invalid verified crate manifest")
                manifest_data = tomllib.loads(archive.extractfile(member).read(MAX_DOCUMENT + 1).decode("utf-8"))
                declaration = manifest_data["package"]
                if declaration.get("name") != package["name"] or declaration.get("version") != package["version"] or (declaration.get("license") or "see bundled license file") != package["license"]:
                    raise ValueError("Cargo metadata differs from verified crate manifest")
                verified_manifest = True
            legal = bool(LEGAL_NAME.fullmatch(path.name))
            sqlite = package["name"] == "libsqlite3-sys" and relative == "sqlite3/sqlite3.c"
            if not legal and not sqlite:
                continue
            if not member.isfile() or relative in seen:
                raise ValueError("nonregular or duplicate legal member")
            seen.add(relative)
            if legal:
                if member.size > MAX_DOCUMENT:
                    raise ValueError("legal member exceeds bound")
                documents.append((relative, checked_text(archive.extractfile(member).read(MAX_DOCUMENT + 1), relative)))
            if sqlite:
                head = archive.extractfile(member).read(8192).decode("utf-8")
                comments = re.findall(r"/\*.*?\*/", head, re.S)
                dedication = next((s for s in comments if "The author disclaims copyright" in s and "May you share freely" in s), None)
                if dedication is None:
                    raise ValueError("bundled SQLite dedication not recognized")
                documents.append((relative + " (copyright dedication)", dedication.encode()))
    if not verified_manifest:
        raise ValueError("verified crate manifest missing")
    if not documents:
        raise ValueError(f"no legal material found: {prefix}")
    if package["name"] == "libsqlite3-sys" and not any("dedication" in p for p, _ in documents):
        raise ValueError("bundled SQLite dedication missing")
    return sorted(documents)


def runtime_documents(target: str) -> list[tuple[str, bytes]]:
    rust = run(["rustc", "--version"], 4096).strip()
    if not rust.startswith("rustc 1.91.1 "):
        raise ValueError("release legal inventory requires pinned Rust 1.91.1")
    sysroot = Path(run(["rustc", "--print", "sysroot"], 4096).strip())
    target_lib = sysroot / "lib/rustlib" / target / "lib/self-contained"
    if not (target_lib / "libc.a").is_file():
        raise ValueError("installed static-musl target runtime missing")
    doc = sysroot / "share/doc/rust"
    copyright_text = read_document(doc / "COPYRIGHT-library.html", "Rust library copyright")
    # The full rustup document includes transitive standard-library dependencies.
    # Some repackaged Rust distributions omit them; those are not release inputs.
    if b"<h3>" not in copyright_text or b"libc-" not in copyright_text:
        raise ValueError("installed Rust library copyright inventory is incomplete")
    result = [("Rust 1.91.1 / COPYRIGHT-library.html", copyright_text),
              ("musl 1.2.3 / COPYRIGHT (upstream)", MUSL_NOTICE),
              ("Rust 1.91.1 / library/compiler-builtins/LICENSE.txt", COMPILER_BUILTINS_NOTICE)]
    license_files = sorted((doc / "licenses").glob("*.txt"))
    required = {"MIT.txt", "Apache-2.0.txt", "LLVM-exception.txt", "NCSA.txt", "GCC-exception-3.1.txt", "GPL-3.0-or-later.txt"}
    if not required.issubset({p.name for p in license_files}):
        raise ValueError("installed Rust license texts missing")
    for path in license_files:
        result.append((f"Rust 1.91.1 / licenses/{path.name}", read_document(path, path.name)))
    # These Debian-format files preserve upstream notices and full non-common
    # texts; append referenced common-license texts below rather than leaving
    # machine-local /usr/share/common-licenses references unresolved.
    for label, path in [("Installed musl toolchain copyright", Path("/usr/share/doc/musl/copyright")),
                        ("Installed GCC runtime copyright", Path("/usr/share/doc/libgcc-s1/copyright"))]:
        data = read_document(path, label)
        result.append((label, data))
        references = set(re.findall(rb"/usr/share/common-licenses/([A-Za-z0-9.+_-]+)", data))
        for name in sorted(references):
            filename = name.decode().rstrip(".")
            result.append((f"Installed toolchain common license / {filename}", read_document(Path("/usr/share/common-licenses") / filename, filename)))
    # The pinned Rust release's musl-toolchain.sh specifies musl 1.2.3. Require
    # that upstream version's complete notice in the installed toolchain file.
    musl = next(data for label, data in result if label == "Installed musl toolchain copyright")
    if b"musl" not in musl.lower() or b"Permission is hereby granted" not in musl:
        raise ValueError("musl copyright is not a complete notice")
    return result


def generate(repo: Path, target: str) -> tuple[bytes, int, int]:
    if sys.platform != "linux" or platform.machine() != TARGETS[target]:
        raise ValueError("run on the native Linux architecture used for this release")
    packages = selected_packages(repo, target)
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    documents: dict[bytes, list[str]] = {}
    def add(label: str, data: bytes) -> None:
        checked_text(data, label)
        documents.setdefault(data, []).append(label)
    add("Nodomio / LICENSE", read_document(repo / "LICENSE", "project LICENSE"))
    for package in packages:
        for path, data in archive_documents(package, cargo_home):
            add(f'{package["name"]} {package["version"]} / {path}', data)
    for label, data in runtime_documents(target):
        add(label, data)
    chunks = [b"Nodomio Agent - licenses and third-party notices\n\n",
              f"Target: {target}\nRust toolchain: 1.91.1\n".encode(),
              b"Cargo inventory: active normal dependency graph from the locked release build.\n"
              b"This conservative inventory includes helper crates and installed toolchain legal\n"
              b"materials; presence does not assert that every component contributes linked code.\n"
              b"Crate archives were verified against Cargo.lock SHA-256 checksums. Identical\n"
              b"documents are retained once with every source reference. Original notice bytes\n"
              b"are preserved. SQLite's dedication is reproduced from its bundled amalgamation.\n"
              b"Rust static musl build provenance: rust-lang/rust tag 1.91.1,\n"
              b"src/ci/docker/scripts/musl-toolchain.sh (MUSL_VER=1.2.3).\n\n"
              b"DEPENDENCY INVENTORY (name version; declared license; archive SHA-256)\n"]
    for package in packages:
        chunks.append(f'{package["name"]} {package["version"]}; {package["license"]}; {package["checksum"]}\n'.encode())
    ordered = sorted(documents.items(), key=lambda item: hashlib.sha256(item[0]).hexdigest())
    for data, labels in ordered:
        digest = hashlib.sha256(data).hexdigest()
        chunks.append(f"\n{'=' * 72}\nDOCUMENT SHA-256: {digest}\nSources:\n".encode())
        for label in sorted(set(labels)):
            chunks.append(f"  {label}\n".encode())
        chunks.extend([b"\n", data, b"\n"])
    output = b"".join(chunks)
    if len(output) > MAX_BUNDLE:
        raise ValueError(f"legal bundle exceeds {MAX_BUNDLE}-byte package limit ({len(output)} bytes)")
    if b"\x00" in output:
        raise ValueError("NUL in generated legal bundle")
    return output, len(packages), len(documents)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--output", required=True, type=Path, help="new consolidated LICENSE file")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    temporary = None
    try:
        output, packages, documents = generate(repo, args.target)
        with tempfile.NamedTemporaryFile(dir=args.output.parent, prefix=".agent-license-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic publication without overwriting an existing output or symlink.
        os.link(temporary, args.output)
        print(json.dumps({"bytes": len(output), "registryPackages": packages,
                          "uniqueDocuments": documents, "sha256": hashlib.sha256(output).hexdigest()}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        # Avoid leaking local paths or subprocess diagnostics into release logs.
        print(f"license bundle failed: {type(error).__name__}: {error}" if isinstance(error, ValueError)
              else f"license bundle failed: {type(error).__name__}", file=sys.stderr)
        return 1
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
