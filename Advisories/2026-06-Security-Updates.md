# Security Updates - Nightingale (June 2026)

**Title:** Security Updates - Nightingale (June 2026)

Use this body when publishing at https://github.com/RAJANAGORI/Nightingale/security/advisories/new

### Summary
We have addressed multiple CVEs originating from third-party dependencies in Nightingale versions **1.1.31** and above, across **arm64** and **amd64** architectures. Images: [`ghcr.io/rajanagori/nightingale:stable`](https://ghcr.io/rajanagori/nightingale), [`ghcr.io/rajanagori/nightingale:arm64`](https://ghcr.io/rajanagori/nightingale).

| Package | Remediation | CVE | Severity |
| :------ | :---------: | :-: | :------: |
| Go stdlib (embedded binaries) | Rebuild with Go 1.26.3+ | Multiple | High |
| libcups2t64 | Removed | CVE-2026-34980 | High |
| libfreerdp-client3-3 | Removed | Multiple | High |
| libfreerdp2-2 | Removed | Multiple | High |
| libfreerdp3-3 | Removed | Multiple | High |
| libgbm1 | Removed | Multiple | High |
| libgl1-mesa-dri | Removed | Multiple | High |
| libglx-mesa0 | Removed | Multiple | High |
| libwinpr2-2 | Removed | Multiple | High |
| libwinpr3-3 | Removed | Multiple | High |
| linux-libc-dev | Removed | Multiple | High |
| mesa-libgallium | Removed | Multiple | High |
| steghide | Removed | Multiple | High |
| @isaacs/brace-expansion | Patched (>=5.0.1) | CVE-2026-25547 | High |
| axios | Patched (>=1.16.0) | Multiple | High |
| cross-spawn | Patched (>=7.0.5) | CVE-2024-21538 | High |
| glob | Patched (>=11.1.0) | CVE-2025-64756 | High |
| minimatch | Patched (>=10.2.3) | Multiple | High |
| path-to-regexp | Patched (>=8.4.0) | CVE-2026-4926 | High |
| socket.io-parser | Patched (>=4.2.6) | CVE-2026-33151 | High |
| tar | Patched (>=7.5.11) | Multiple | High |
| tmp | Patched (>=0.2.6) | CVE-2026-44705 | High |
| io.airlift:aircompressor | Upgrade to 2.0.3 | Multiple | High |
| io.netty:netty-codec | Upgrade to 4.1.133.Final | Multiple | High |
| io.netty:netty-codec-http | Upgrade to 4.2.13.Final, 4.1.133.Final | Multiple | High |
| org.bitbucket.b_c:jose4j | Upgrade to 0.9.6 | Multiple | High |
| org.eclipse.jetty:jetty-http | Upgrade to 12.1.7, 12.0.33 | Multiple | High |
| org.eclipse.jetty:jetty-server | Upgrade to 12.1.6, 12.0.32 | Multiple | High |

> Remediations applied during the Docker build via `configuration/cve-mitigation/`:
> - CVE-2022-21221
> - CVE-2024-21538
> - CVE-2024-24790
> - CVE-2024-29371
> - CVE-2024-34156
> - CVE-2024-7254
> - CVE-2025-15558
> - CVE-2025-22869
> - CVE-2025-22874
> - CVE-2025-27152
> - CVE-2025-59375
> - CVE-2025-61594
> - CVE-2025-61726
> - CVE-2025-61729
> - CVE-2025-64756
> - CVE-2025-65637
> - CVE-2025-67030
> - CVE-2025-67721
> - CVE-2025-68121
> - CVE-2025-69720
> - CVE-2026-0994
> - CVE-2026-1605
> - CVE-2026-2332
> - CVE-2026-23745
> - CVE-2026-23949
> - CVE-2026-23950
> - CVE-2026-24051
> - CVE-2026-24842
> - CVE-2026-24882
> - CVE-2026-25210
> - CVE-2026-25547
> - CVE-2026-25639
> - CVE-2026-25679
> - CVE-2026-26269
> - CVE-2026-26960
> - CVE-2026-26996
> - CVE-2026-27820
> - CVE-2026-27903
> - CVE-2026-27904
> - CVE-2026-28417
> - CVE-2026-28421
> - CVE-2026-29181
> - CVE-2026-29786
> - CVE-2026-31802
> - CVE-2026-32280
> - CVE-2026-32281
> - CVE-2026-32283
> - CVE-2026-33151
> - CVE-2026-33186
> - CVE-2026-33412
> - CVE-2026-33811
> - CVE-2026-33814
> - CVE-2026-33870
> - CVE-2026-34040
> - CVE-2026-34980
> - CVE-2026-34982
> - CVE-2026-34986
> - CVE-2026-35177
> - CVE-2026-39820
> - CVE-2026-39823
> - CVE-2026-39825
> - CVE-2026-39826
> - CVE-2026-39836
> - CVE-2026-39881
> - CVE-2026-39883
> - CVE-2026-41316
> - CVE-2026-41567
> - CVE-2026-42033
> - CVE-2026-42035
> - CVE-2026-42043
> - CVE-2026-42245
> - CVE-2026-42246
> - CVE-2026-42257
> - CVE-2026-42258
> - CVE-2026-42306
> - CVE-2026-42482
> - CVE-2026-42483
> - CVE-2026-42484
> - CVE-2026-42496
> - CVE-2026-42497
> - … and 24 more (see Trivy remediation plan)

### Fixed Releases
| Name | Affected Versions | Fix Version |
| ---- | :---------------: | :---------: |
| nightingale (Docker) | Below 1.1.31 | 1.1.31 |
| nightingale-go | 1.1.30 to prior fix | 1.1.31 |
| nightingale-go | 1.0 | Not Supported |

### Suggestion
Pull the latest Nightingale image tags (`stable`, `arm64`) or upgrade `nightingale-go` to **1.1.31** from [Releases](https://github.com/RAJANAGORI/Nightingale/releases).

After upgrading, re-run the [Trivy Scan](https://github.com/RAJANAGORI/Nightingale/actions/workflows/trivy.yml) workflow so resolved findings are closed on the [Code scanning](https://github.com/RAJANAGORI/Nightingale/security/code-scanning) tab.

### Awaiting upstream Debian fixes

The following runtime packages still report HIGH/CRITICAL CVEs with no fixed version in Debian stable at scan time. `debian-apt-security.sh` applies fixes automatically on each image rebuild once published:

`curl`, `gpgv`, `hashcat-data`, `libcups2t64`, `libcurl3t64-gnutls`, `libcurl4t64`, `libexpat1`, `libncursesw6`, `libperl5.40`, `libplexus-utils2-java`, `libprotobuf32t64`, `libpython3.13-minimal`, `libpython3.13-stdlib`, `libruby3.3`, `libssh2-1t64`, `libtinfo6`, `libxml2`, `ncurses-base`, `ncurses-bin`, `perl`, … (12 more)
