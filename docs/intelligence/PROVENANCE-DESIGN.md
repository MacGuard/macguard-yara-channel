# Software Provenance Engine: design and evidence survey

Status: design v1.0.0 draft. Companion files: `schemas/file-provenance.schema.json` (JSON Schema 2020-12), `fixtures/provenance/*.json` (three hand-made documents that validate against the schema).

## Resumen en español

Este documento diseña el motor de procedencia de software por archivo (también paquete, aplicación, contenedor y host) de MacGuard. Lo central:

- Se separan **seis hechos** que casi siempre se mezclan: `CONTENT_ORIGIN` (de dónde vienen los bytes), `INSTALLATION_METHOD` (cómo llegaron al disco), `PACKAGE_OWNERSHIP` (qué paquete reclama el archivo), `INTEGRITY_STATUS` (si coincide con una referencia), `PROVENANCE_CONFIDENCE` (cuánto se fía el motor de los cuatro anteriores) y `DETECTION_STATUS` (resultado de YARA/AV/IOC). Cada uno tiene su vocabulario; ninguno se deduce de otro.
- Reglas duras: nunca inferir procedencia por la ruta; nunca decir que un binario es del repositorio oficial porque hoy exista un paquete con ese nombre; un SHA-256 calculado no es integridad (hace falta una referencia: checksum de la base de paquetes, firma, manifiesto, atestación); lo desconocido se representa y nunca se muestra como seguro; se registran siempre las evidencias contradictorias y las ausencias.
- Se probaron en este Mac los mecanismos reales (Homebrew, cask, pkgutil, xattr de cuarentena, codesign/spctl, pip, npm, cargo, go, docker, git). Hallazgos que cambian el diseño: Homebrew no guarda hash por archivo y **reubica** los Mach-O al instalar, así que no se puede comparar byte a byte con la botella; los xattr de cuarentena son escribibles por cualquier proceso del usuario y `mdls` devuelve vacío fuera del índice de Spotlight; una app instalada con cask no tenía cuarentena mientras que las descargas manuales la conservan; `/usr/bin/git` y `/bin/ls` no pertenecen a ningún recibo `pkgutil`; el `RECORD` de pip de paquetes entregados por Apple no coincide en 21 archivos `.py`.
- Para instalaciones antiguas la reconstrucción es parcial o imposible: `curl | sh` no deja nada; los logs rotan; los xattr se pierden al copiar. El motor lo declara en `coverage.historical_reconstruction`.
- Fase 1 recomendada: macOS (firma de código/notarización, cuarentena, recibos pkgutil, Homebrew, MAS) y Linux dpkg/rpm/pacman (bases de datos con propietario y checksums), más hash-sólo-con-ausencias para lo demás.

The rest of the document is in English.

## 1. Principles and hard rules

| # | Rule | Consequence in the engine |
|---|---|---|
| R1 | Never infer provenance from the path alone. | `PATH_LOCATION` evidence is recorded with trust `HEURISTIC` and may not support any claim (the schema forbids `supports` on it). |
| R2 | A package with the same name in an official repository today does not make an installed binary official. | The current catalog / `apt-cache policy` / `brew info` candidate is recorded as `NAME_COLLISION_NOTE` (no `supports`). Origin comes only from records of the installation or from bytes matched to a reference. |
| R3 | A computed hash is not integrity. | `integrity_status` is `NO_REFERENCE` when the only evidence is `HASH_ONLY`. `VERIFIED_INTACT` and `MODIFIED` require `reference.kind != NONE` (schema-enforced). |
| R4 | Contradicting evidence and absences are always stored. | Evidence has `present:false` for "looked for, not found" and a `contradicts` list; both feed `provenance_confidence`. |
| R5 | Unknown is a value and is never rendered as safe. | Every field has `UNKNOWN` (or `NO_REFERENCE`, `NOT_SCANNED`, `OWNERSHIP_NOT_QUERYABLE`). The vocabulary contains no `SAFE`, `TRUSTED`, `CLEAN`. UI copy for unknown is "cannot say", never green. `SCANNED_NO_MATCH` reads "these rules found nothing", never "clean". |
| R6 | A reference stored where the file's attacker can also write is weak. | `reference_location_writable_by_attacker` is recorded; a same-account-writable reference caps integrity at `PARTIALLY_VERIFIED` unless it is cryptographically signed. |
| R7 | Never upgrade silently. | Confidence can only rise through explicit rules in section 5, and only by new evidence; a later scan never overwrites an earlier assessment, it appends a document with a history link. |
| R8 | Old installs are reconstructed only as far as records exist, and the limit is declared. | `coverage.historical_reconstruction` is `FULL`, `PARTIAL` or `NONE`; history entries carry `known_via` and `reliability`. |

## 2. The six facts and their vocabularies

They are independent. A file can be `REGISTERED_REPOSITORY` origin yet `MODIFIED`; `NOT_OWNED` yet `VENDOR_DIRECT`; `HIGH` confidence and `MATCHED` by YARA.

| Field | Question | Values |
|---|---|---|
| `content_origin` | Where did these bytes come from? | `OS_VENDOR`, `REGISTERED_REPOSITORY`, `THIRD_PARTY_REPOSITORY`, `VENDOR_DIRECT`, `USER_DOWNLOAD_RECORDED`, `LOCAL_BUILD`, `CONTAINER_IMAGE`, `UNKNOWN`. Plus `claim_basis`: `VERIFIED_BINDING`, `DECLARED_BY_MANAGER`, `DECLARED_BY_WRITABLE_METADATA`, `INFERRED`, `NONE` (required with `UNKNOWN`). |
| `installation_method` | How did they get onto disk? | `SYSTEM_PACKAGE_MANAGER`, `THIRD_PARTY_PACKAGE_MANAGER`, `LANGUAGE_PACKAGE_MANAGER`, `PKG_INSTALLER`, `APP_BUNDLE_COPY`, `SELF_CONTAINED_BUNDLE`, `SOURCE_INSTALL`, `CONTAINER_RUNTIME`, `MANUAL_COPY`, `SCRIPT_OR_PIPE_UNRECORDED`, `UNKNOWN`. |
| `package_ownership` | Which package claims this path? | `OWNED_BY_PACKAGE`, `OWNED_BY_MULTIPLE_PACKAGES`, `GENERATED_BY_PACKAGE_SCRIPT`, `NOT_OWNED` (only if every applicable database was read successfully), `OWNERSHIP_NOT_QUERYABLE`, `UNKNOWN`. |
| `integrity_status` | Do the bytes match a reference, which one? | `VERIFIED_INTACT`, `MODIFIED`, `PARTIALLY_VERIFIED`, `REFERENCE_UNTRUSTED`, `NO_REFERENCE`, `UNKNOWN`; plus `reference.{kind, authority, strength, scope, reference_location_writable_by_attacker}`. |
| `provenance_confidence` | How far can the engine trust the origin/ownership claims together? | `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `VERY_HIGH` + `contradicted`, `capped_from`, `cap_rule_ids`, `independent_sources`. |
| `detection_status` | What did YARA/AV/IOC say? | `NOT_SCANNED`, `SCANNED_NO_MATCH`, `MATCHED`, `SCAN_ERROR`, `SCAN_PARTIAL`, `RESULT_STALE`, `UNKNOWN`. Says nothing about provenance. |

Why `package_ownership` is not `content_origin`: ownership is a statement in a local database ("package P claims path F"); origin is about the bytes. An attacker who replaces F keeps the owner entry. Why `integrity_status` is not confidence: integrity compares bytes with a reference; confidence summarizes everything including how reliable the reference is.

## 3. Data model

One document per subject (`subject.kind` = `file`, `package`, `application`, `container`, `host`; the host and package documents aggregate file documents, section 6).

**File identity** (`subject.file`): `path` (home replaced by `~`, identifier only), `path_was_symlink`, `resolved_path`, `device`, `inode`, `size`, `mode`, `uid_class`, `mtime_ns`, `ctime_ns`, `birthtime_ns`, `hashes.sha256` (required) and `sha512`, `stable_during_read`, `file_type`, `architecture`, `code_signature_summary`. The tuple (device, inode, size, mtime_ns, ctime_ns) is the cache key: if it changes the assessment is stale. Hashing uses one file descriptor opened with `O_NOFOLLOW` (and `O_NONBLOCK`, regular files only), with stat before and after.

**Ownership chain** (`ownership_chain`): `file -> package -> manager -> repository -> source`. Each link has `resolution`: `RESOLVED`, `UNRESOLVED`, `NOT_QUERYABLE`, `CONFLICT`. Unresolved links are listed, never omitted. For Homebrew the source link is usually `UNRESOLVED`: the bottle is Homebrew's build of an upstream tarball that the engine did not re-verify.

**Evidence** (`evidence[]`): `{id, kind, present, source{type, command_or_api, scope, exit_status, needs_root, needs_network}, observed_at, trust, independence_group, supports[], contradicts[], summary, raw_digest}`.

- `trust`: `CRYPTOGRAPHIC` (verified chain or attestation), `SYSTEM_AUTHORITATIVE` (OS-protected database or API), `MANAGER_DECLARED` (written by the manager, editable by the same account), `WRITABLE_METADATA` (xattrs, user logs, lockfiles), `HEURISTIC`. Schema forces quarantine/WhereFroms/provenance xattrs to `WRITABLE_METADATA` and `HASH_ONLY`/`PATH_LOCATION`/`NAME_COLLISION_NOTE`/`TIMESTAMP_CORRELATION` to `HEURISTIC` with no `supports`.
- `independence_group`: evidence from the same database or writer counts once. `brew info` and the receipt share the group `brew-cellar`; quarantine and WhereFroms share `xattr-writer`.
- `supports`/`contradicts`: `{field, value, weight}`, naming which of the six fields and which value the evidence bears on.

**History** (`history[]`): `{at, at_precision, change, known_via, reliability, from_sha256, to_sha256, evidence_ids}`. `known_via`: `ENGINE_SNAPSHOT_DIFF` (reliability HIGH: two engine observations with hashes), `PACKAGE_MANAGER_LOG`, `MANAGER_HISTORY_DB`, `FILESYSTEM_TIMESTAMP` (LOW; any process can set it), `INFERRED`. The engine cannot know about changes before its first observation; `FIRST_SEEN_BY_ENGINE` says exactly that.

**Attestations** (`attestations[]`): kind (SLSA, Sigstore, PEP 740, npm provenance, GitHub attestation, APT Release signature, RPM signature, notarization ticket, cosign, SBOM), `availability` (`AVAILABLE_VERIFIED`, `AVAILABLE_UNVERIFIED`, `VERIFICATION_FAILED`, `NOT_FOUND`, `NOT_CHECKED`, `NOT_APPLICABLE`), whether the subject digest matches the file. `NOT_CHECKED` is a gap, not a failure.

**Links**: `links.detections[]` (engine, ruleset version, result, scanned sha256: the detection pipeline owns the result, provenance only points to it) and `links.vulnerabilities[]` (id, source, `match_basis`, `match_confidence`). A vulnerability may be linked through a package identity only when `package_ownership` is `OWNED_BY_PACKAGE`; `NAME_ONLY` matches are always `LOW`. A modified file owned by a vulnerable package version keeps the link but carries `integrity_status=MODIFIED`.

**Coverage** (`coverage`): manager or method, `state` (`IMPLEMENTED`, `DESIGNED`, `NOT_POSSIBLE`), `historical_reconstruction`, `limits[]`.

## 4. Real evidence per manager (coverage matrix)

No provenance engine code exists in this worktree. The coverage column therefore means: `implemented` = the evidence mechanism was exercised by experiment on this Mac in this survey and is v1 scope (the engine code itself is still to be written); `designed` = specified here but not exercised on this host; `not-possible` = the act leaves no evidence. Rows marked "(not run here)" are from documented behavior of the tool, not from an experiment on this machine (this Mac has no dpkg, rpm, pacman, flatpak, snap). Treat them as hypotheses to confirm on a real Linux host (test plan, section 10).

Columns: Evidence sources and exact read-only commands/APIs | Proves | Does NOT prove | Reliability | Offline? | Root? | Platform | Coverage today.

### 4.1 Linux system package managers

| Manager | Sources and commands | Proves | Does NOT prove | Reliab. | Offline / root | Platform | Coverage |
|---|---|---|---|---|---|---|---|
| APT / aptitude / DPKG, ownership | `dpkg -S <path>` (reads `/var/lib/dpkg/info/*.list`); `dpkg-query -S`; `/var/lib/dpkg/info/<pkg>.list` | Package P lists that path | Bytes are P's; a replaced file keeps its owner. Misses alternatives symlinks, diversions and files created by maintainer scripts; usr-merge paths (`/bin` vs `/usr/bin`) need normalizing | High for the claim, none for content | Offline, no root | Debian family | designed |
| DPKG integrity | `dpkg -V <pkg>` / `dpkg --verify`; `/var/lib/dpkg/info/<pkg>.md5sums`; `debsums` | MD5 of the file equals the MD5 recorded at install | Anything cryptographic: MD5 is weak and the reference sits on the same disk, root-writable (R6). Packages without `md5sums` (many) have no per-file reference. Config files use `conffiles` hashes (modified on purpose) | Medium (`PARTIALLY_VERIFIED` at best, `reference.strength=WEAK_HASH`) | Offline; root needed only to read all files | Debian family | designed |
| APT repository / signatures | `apt-cache policy <pkg>`; `/var/lib/apt/lists/*_Release`, `*_InRelease`; `/etc/apt/sources.list{,.d}`, keyrings; `apt-get download` + `dpkg-deb` + SHA256 from `Packages` | Which sources offer which versions now; Release was signature-checked at `apt update` time (apt refuses unsigned unless configured) | Where the installed copy came from. A version no longer offered shows only `/var/lib/dpkg/status`. A source offering the same version now is a name collision (R2) | Low for installed origin; High for "Release signed by key K at time T" | Offline for local lists; network to re-download | Debian family | designed |
| APT history | `/var/log/dpkg.log*`, `/var/log/apt/history.log*`, `term.log*` | A transaction installed/upgraded P at time T, with command line (history.log) | Source repository; log may be rotated away or edited by root; `dpkg -i` installs of a local `.deb` appear without origin | Medium; `known_via=PACKAGE_MANAGER_LOG` | Offline; root to read | Debian family | designed |
| RPM / DNF / Zypper ownership | `rpm -qf <path>` (rpmdb at `/var/lib/rpm`, sqlite/ndb/bdb) | Package P claims the path; `rpm -q --qf` also gives install time, vendor, build host | Bytes; scriptlet-created files | High for the claim | Offline; no root for read in most setups | RPM family | designed |
| RPM integrity | `rpm -V <pkg>` (per-file digest SHA-256 on modern packages, size, mode, owner, mtime: flags `S M 5 D L U G T P`); `rpm -q --qf '%{SIGPGP:pgpsig}'`; `rpm --checksig <file.rpm>` (needs the `.rpm`); `rpm -qa gpg-pubkey` | Installed file differs or not from the digest in the package header; the header carries the vendor signature id recorded at install | That the rpmdb itself is untampered (root-writable); `--checksig` needs the original rpm, absent for old installs | Medium-High (digest is real hash, db is local) | Offline; root for full `-Va` | RPM family | designed |
| DNF / Zypper install source | `dnf history list/info` (`/var/lib/dnf/history.sqlite`); `dnf repoquery --installed --qf '%{from_repo}'` or `dnf info installed` ("From repo"); `/var/log/zypp/history` (pipe-separated, includes repo alias and package checksum) | The repo alias the manager recorded at install time (better than APT); `@System` or `@commandline` marks local rpm installs | That the repo alias still points to the same URL; alias is user-editable text | Medium; `DECLARED_BY_MANAGER` | Offline; root | RPM family | designed |
| Pacman | `pacman -Qo <path>` (`/var/lib/pacman/local/*/files`); `pacman -Qkk` (checks `mtree`: size, mode, mtime, sha256/md5 per file); `pacman -Qi` (`Validated By: Signature` or `SHA256 Sum`, `Install Reason`); `/var/log/pacman.log` (`[ALPM] installed`) | Owner; per-file hash in mtree; how the package was validated at install | Which repository the package came from (local db does not store it; `pacman -Si`/`-Sl` report the repo **now**: R2). `-Qm` foreign packages are only "not in any current sync db" (could be AUR, could be a repo since removed) | High for owner + integrity (but mtree is on the same disk) | Offline; root for full check | Arch family | designed |

### 4.2 Linux self-contained formats

| Method | Sources and commands | Proves | Does NOT prove | Reliab. | Offline / root | Coverage |
|---|---|---|---|---|---|---|
| Flatpak | `flatpak info --show-origin --show-commit <app>`; deploy data under `<install>/app/<id>/<arch>/<branch>/active/`; OSTree repo `ostree --repo=<r> fsck` / `flatpak repair --dry-run` | Remote name and commit id of the deployment; object store content-addressed; commits signed per remote (GPG/collection) | That the remote is who it claims today; the checked-out deploy vs object store consistency should be checked, not assumed | High if signature verification is enabled for the remote | Offline; no root for user installs | designed |
| Snap | `snap list --all`, `snap info`; `/var/lib/snapd/snaps/*.snap` (read-only squashfs); assertions `/var/lib/snapd/assertions` (`snap-revision` with sha3-384 of the snap, signed by the Store) | Snap file hash vs Store-signed assertion; mounted content is read-only | Anything about files outside the squashfs; `--dangerous` or sideloaded snaps have no assertion (record `ASSERTION_ABSENT`) | High | Offline; root to read assertions | designed |
| AppImage | ELF + squashfs; optional embedded signature section (`.sha256_sig`, `.sig_key`); update info section (`.upd_info`, e.g. `gh-releases-zsync|owner|repo|...`); integration `.desktop` files | Declared update channel; signature if present and validated by a tool | Origin: no registry, no database. Most AppImages are unsigned: `NO_REFERENCE` | Low | Offline; no root | designed |
| Homebrew on Linux | Same as macOS Homebrew (4.3) with prefix `/home/linuxbrew/.linuxbrew`; ELF patched for rpath at pour time | Same as 4.3 | Same as 4.3; relocation changes ELF bytes | Medium | Offline | designed |

### 4.3 macOS

Experiments were run here (section 8).

| Method | Sources and commands | Proves | Does NOT prove | Reliab. | Offline / root | Coverage |
|---|---|---|---|---|---|---|
| Homebrew formula | `brew --prefix` (here `/usr/local`); keg `<prefix>/Cellar/<f>/<v>/INSTALL_RECEIPT.json` (JSON parse only: `tap`, `poured_from_bottle`, `installed_on_request`, `time`, `runtime_dependencies`, `changed_files`, `built_on`, `source.tap_git_head`); `brew info --json=v2 <f>`; formula API index (JWS-signed) for bottle sha256 | Keg exists with this receipt; bottle sha256 for the archive (reference for the archive, not for installed files) | **No per-file hash is stored locally.** Bottle pour **relocates** files: Mach-O load commands and text placeholders are rewritten, so installed bytes differ from the bottle's (verified: `otool -L` on an installed binary shows absolute `/usr/local/...` paths). Core receipts here have `tap_git_head: null` (API install), so no commit pin. Receipt/Cellar are writable by the installing account. A symlink in `bin/` pointing into the Cellar is not evidence | Medium for ownership/origin claim, `NO_REFERENCE` for content unless opt-in network comparison on non-relocated files (docs, data) | Offline for local part; network for bottle compare; no root | designed (read of receipt + `brew info` implemented in v1) |
| Homebrew cask | `<prefix>/Caskroom/<c>/.metadata/INSTALL_RECEIPT.json`, `config.json`, `.metadata/<ver>/<ts>/Casks/<c>.json` (snapshot of the cask definition at install time, with `url`, `sha256`); `brew info --json=v2 --cask` for the **current** catalog | What cask version was installed and what download sha256 the cask declared then; `tap_git_head` pins the cask repository commit | That the app on disk is that download's content (cask sha256 covers the archive, not the installed bundle); apps can be updated by the app itself (`auto_updates`), diverging from the receipt. Observed: current catalog version/sha differ from the installed one, so the catalog may never be used as origin evidence (R2) | Medium; bundle code signature gives the integrity reference | Offline; no root | designed (v1) |
| Taps | `brew tap`, `Library/Taps/<org>/homebrew-<repo>` git repos; receipt `source.tap` | Which tap the formula/cask came from | That the tap is trusted; third-party tap = `THIRD_PARTY_REPOSITORY` | Medium | Offline | designed |
| PKG installer | `pkgutil --pkgs`; `pkgutil --pkg-info <id>` (version, location, install-time); `pkgutil --file-info <path>` (owner pkgid, mode, uid, gid); `pkgutil --files <id>`; receipts and BOMs under `/var/db/receipts`; `pkgutil --check-signature <file.pkg>` (for a pkg file) | A package with this id claimed the path at install time; time of install | Bytes are unmodified: **the receipt BOM holds only a CRC-style checksum and metadata, not a strong digest**, and the BOM for an Apple pkg was not even present at the conventional path in this survey. No receipt for a drag-and-drop install. SIP-sealed system files and `/usr/bin` shims are not owned by any receipt | Medium for ownership; Low for integrity | Offline; no root to query | implemented (v1) |
| DMG / APP drag install | App bundle xattrs and signature (below); original DMG usually deleted | Only what remains on the bundle | Anything about the DMG, mounting, or who ran the copy | Low | Offline | implemented (v1) |
| Quarantine xattr | Read `getxattr(com.apple.quarantine)` directly (value `flags;hex-timestamp;agent;event-UUID`), do not use `mdls`; the origin URL lives in the per-user LaunchServices quarantine events database (personal data, not read) | A quarantine-aware downloader tagged this file at time T with agent A | Origin URL (not in the xattr); that nobody forged or stripped it. Any process of the user can write or delete it (experiment 9). Absence proves nothing: cask installs, `curl`, `cp` and archive tools may not set or may drop it; removal is a normal user action | Low (`WRITABLE_METADATA`) | Offline; no root | implemented (v1) |
| `kMDItemWhereFroms` | Read the xattr `com.apple.metadata:kMDItemWhereFroms` (binary plist of URLs) directly; `mdls -name kMDItemWhereFroms` only works for files in the Spotlight index | Declared download URL and referrer | The URL is the truth (editable); `mdls` returns `(null)` for non-indexed locations (experiment 9), so a `(null)` is "not obtainable", not "absent" | Low | Offline | implemented (v1) |
| `com.apple.provenance` xattr | `xattr -l` | Presence only: macOS (Sequoia) marks files touched by provenance-tracking processes | Origin, publisher, or any URL. Observed on nearly everything (brew files, copies we made) | None as origin | Offline | recorded as `PROVENANCE_XATTR`, supports nothing |
| Code signature, notarization, Gatekeeper | `codesign -dv --verbose=2 <path>`; `codesign --verify --deep --strict <path>`; `spctl --assess --type execute -vv <app>` (prints `source=Notarized Developer ID` / `Mac App Store` / `Apple System`); `codesign -d --entitlements` | Signer identity (Team ID) and that sealed contents are unchanged since signing; Apple notarization accepted the build | Origin of the copy (a signed app may be re-hosted); ad hoc signatures prove nothing about who signed (anyone can re-sign; experiment 9 shows a modified ad hoc binary fails verification, but a re-signed one passes) | High for integrity of sealed code when Developer ID/App Store/Apple; none for ad hoc origin | Offline (revocation checks may go online); no root | implemented (v1) |
| Mac App Store | `_MASReceipt` in the bundle, `xattr` `com.apple.appstore.*`, `spctl` `source=Mac App Store` | Distributed through MAS (signature chain Apple) | Which Apple ID; receipts are validated by the app, not by us | High | Offline | implemented (v1) |
| Manual downloads | Quarantine + WhereFroms + signature; the file in `~/Downloads` | See above; `USER_DOWNLOAD_RECORDED` at `DECLARED_BY_WRITABLE_METADATA` | Everything not in xattrs | Low | Offline | implemented (v1) |

### 4.4 Language ecosystems

| Ecosystem | Sources and commands | Proves | Does NOT prove | Reliab. | Offline / root | Coverage |
|---|---|---|---|---|---|---|
| pip / pipx / uv / Poetry | `<site-packages>/<dist>.dist-info/{RECORD,INSTALLER,direct_url.json,REQUESTED,METADATA}`; `importlib.metadata.distributions()`; PEP 740 attestations from the index (network); `pip download --no-deps` + compare | `RECORD` lists files with `sha256=` of what the installer wrote; `INSTALLER` names the tool; `direct_url.json` says VCS/local-path/URL install | `INSTALLER` and `RECORD` are written by the installer, not by an authority: they are editable and a vendor can ship them (experiment 7). Mismatch = contradiction, not proof of tampering. PyPI attestations exist only for packages whose projects publish them | Medium for integrity vs installer record; High only with verified PEP 740 attestation matching the wheel digest | RECORD offline; attestation online; no root | implemented (v1: RECORD, INSTALLER, direct_url) |
| npm / pnpm / Yarn / Bun | `package-lock.json` (`integrity` SHA-512 per tarball, `resolved` URL); `node_modules/.package-lock.json`; `pnpm-lock.yaml`; `yarn.lock` (checksum); `bun.lock`; `npm audit signatures` (registry signatures and provenance attestations; network) | Which tarball (integrity) the lockfile resolved; registry signature/provenance when verified | Integrity of the **installed files** (the hash is of the tarball, not of extracted files; lifecycle scripts can modify). Global installs often have no hidden lockfile (none in this survey) | Medium-High with lockfile+tarball re-hash; Low without | Offline for lockfile; network for audit | designed |
| Cargo | `Cargo.lock` (`checksum` = SHA-256 of the `.crate`); `~/.cargo/.crates.toml`, `.crates2.json` (name, version, source `registry+...` or `path+file://` or `git+...`, features, profile, rustc, target); `~/.cargo/bin/` | What source and version `cargo install` built, and the toolchain | **No hash of the installed binary** and no timestamp; `path+file://` means a local build from an arbitrary directory; the crate checksum covers source, not the binary | Medium for source identity, `NO_REFERENCE` for the binary | Offline; no root | designed |
| Composer | `composer.lock` (`dist.shasum` often empty, `reference`/commit); `vendor/composer/installed.json` | Version, source reference | File integrity of `vendor/` | Low-Medium | Offline | designed |
| RubyGems / Bundler | `Gemfile.lock` (`CHECKSUMS` section in recent Bundler); `gem contents`, `gem list`; `specifications/*.gemspec`; `gem fetch` + compare | Resolved gem and source (rubygems.org); checksum when present | Installed file integrity; checksums are optional in older lockfiles | Low-Medium | Offline | designed |
| Go | `go version -m <binary>` (module path, version, `h1:` module hash, build flags, `vcs.*` if built in a repo, dependency list); `go.sum`; GOSUMDB/GOFLAGS | What module version the binary was built from, per metadata embedded in the file | That the binary was built from it: the metadata is inside the file and travels with any replacement. `h1:` covers module source, not the binary. 147 dependency lines but no digest of the executable | Medium for claim; `NO_REFERENCE` for bytes | Offline for the embedded data | implemented (v1: read buildinfo with `go version -m` or by parsing the section) |
| Maven / Gradle | `.m2/repository/**/*.{sha1,sha256,asc}`, `_remote.repositories`; `gradle/verification-metadata.xml` (checksums, trusted keys); `~/.gradle/caches/modules-2/files-2.1/<g>/<a>/<v>/<sha1>/` | Which repository an artifact came from (`_remote.repositories`), checksums and signatures when verification is enabled | Signature validity requires keyring and policy; legacy `.sha1` files are fetched from the same repository (R6) | Medium with verification-metadata | Offline | designed |
| NuGet | `~/.nuget/packages/<id>/<ver>/.nupkg.metadata` (contentHash, source), `.signature.p7s`; `packages.lock.json` (`contentHash`); `dotnet nuget verify` | Source feed, content hash of the package, author/repository signature | Content of extracted files | Medium | Offline for metadata | designed |

### 4.5 Other methods

| Method | Sources and commands | Proves | Does NOT prove | Reliab. | Offline / root | Coverage |
|---|---|---|---|---|---|---|
| Git | `git remote -v`, `git rev-parse HEAD`, `git log -1 --format=%G?%GS`, `git status --porcelain`, `git describe`; `.git/config` | Which repo and commit the working tree started from; signature status (`N` none, `E` cannot check, `G` good) | That the working tree matches the commit (use status); remote URL may be an ssh alias hiding the host (here `github-macguard` alias in the remote); credentials in URLs must be redacted | Medium; unsigned here (`N`), Homebrew's own checkout `E` | Offline | designed |
| make / CMake / Meson install | `install_manifest.txt` (CMake, in the build dir), `meson-logs/install-log.txt` and `meson install --dry-run`, `config.log`, `Makefile` `install` target | A manifest in the (surviving) build tree lists installed paths | Content origin: build dirs are usually deleted; manifests list names, not hashes | Low | Offline | designed (best-effort search of known build dirs, never a full-disk crawl) |
| Scripts and direct downloads (`curl \| sh`, `wget`, `cp`) | Shell history is private and optional; quarantine/WhereFroms only if a quarantine-aware tool saved it | Nothing recorded by the act itself | **`curl \| sh` leaves nothing**: no receipt, no xattr, no log; the script may install anything anywhere. The engine reports `SCRIPT_OR_PIPE_UNRECORDED` only if evidence exists, otherwise `UNKNOWN` | None | n/a | NOT_POSSIBLE for history |
| Docker / Podman | `docker images --digests`; `docker image inspect <ref>` (`RepoDigests`, `Id`, `RootFS.Layers`, `Config.Labels`); `docker history`; registry manifest (network); `cosign verify`, `cosign verify-attestation`, `syft` SBOM (network or local image) | Image content digest (an image id/digest identifies the bytes), the layers and OCI labels (`org.opencontainers.image.source` etc., declared by the image author); a verified cosign signature/attestation binds a digest to a signer | Origin of a tag: tags move; a dangling `<none>` tag has a digest but no recorded name; labels are unauthenticated; on macOS Docker Desktop the files live in a VM, not on the host filesystem | Medium for digest identity; High only with verified signature/attestation | Offline for local inspect; network for registry/cosign | designed (v1.5) |

### 4.6 Honest reconstruction of OLD installs

| Question | What can be recovered | What cannot |
|---|---|---|
| When was it installed? | dpkg.log/history.log (rotated, ~a year by default on Debian, then gone); `rpm -q --qf %{INSTALLTIME}`; dnf history; pacman.log; pkgutil `install-time`; Homebrew receipt `time` | Anything past log retention; anything for manual installs (file mtime and quarantine timestamp are the only hints and both can be set by any process) |
| Which repository did it come from? | Fedora/openSUSE: recorded repo alias (user-editable, may have changed); Homebrew: tap in receipt | Debian/Ubuntu: **not recorded per install** (apt-cache policy shows today's offer); Arch: not recorded; manual: not recorded |
| Was the file the same then? | Only if the engine snapshotted it earlier (`ENGINE_SNAPSHOT_DIFF`) | Everything before the first engine run: history before first observation is unknowable |
| Who ran the install? | apt `history.log` records the invoking user; sudo logs if retained | Usually nothing |
| Original download | Quarantine agent+timestamp, WhereFroms (if the file was never copied by a tool that dropped xattrs) | The DMG/ZIP, the URL if xattrs were stripped, whether the URL served the same bytes |

## 5. Evidence combination algorithm

Policy version `1.0.0`. Same evidence plus same policy version must give the same assessment (deterministic; tested by golden fixtures).

**Step 0, normalize.** Each probe emits evidence with `present`, `trust`, `independence_group`, `supports`, `contradicts`. A probe that could not run (missing tool, permission, timeout) emits `present:false` plus an entry in the relevant `missing[]`/`unqueryable_managers[]`; it never emits "not owned".

**Step 1, `package_ownership`.**
1. At least one applicable manager database queried successfully and it names a package: `OWNED_BY_PACKAGE`. Several names: `OWNED_BY_MULTIPLE_PACKAGES`.
2. Path listed only as generated (alternatives, ldconfig cache): `GENERATED_BY_PACKAGE_SCRIPT`.
3. All applicable databases queried successfully, none names it: `NOT_OWNED`.
4. Any applicable database unreadable (permission, corrupt, missing tool): `OWNERSHIP_NOT_QUERYABLE` (or the owner if another database named one; the unreadable one goes in `unqueryable_managers`).
5. No applicable manager identified: `UNKNOWN`.
A Cellar path, a `node_modules` path or `/usr/lib` prefix never decides ownership (R1); the database record does.

**Step 2, `integrity_status`.** Choose the strongest reference available for this file, in order: (a) verified code signature or Store-signed assertion (strength `CRYPTOGRAPHIC_SIGNED`); (b) attestation subject digest verified against a trust root; (c) upstream artifact comparison (bytes equal to a file in an archive whose hash is in a signed index); (d) package-database digest (RPM SHA-256, pacman mtree sha256) with `CRYPTOGRAPHIC_UNSIGNED`; (e) lockfile / `RECORD` hash; (f) weak hash (dpkg MD5), metadata only.
- Reference matches: `VERIFIED_INTACT` if strength is (a)-(d) and the reference location is not attacker-writable or is signed; otherwise `PARTIALLY_VERIFIED`.
- Reference exists and does not match: `MODIFIED`. Never softened to "different version" unless the owning package version differs from the reference's version, which is a separate `PACKAGE_DB_METADATA_MISMATCH` evidence and a `contradicts` on ownership.
- Only (e)/(f), or a reference stored beside the file without signature: `PARTIALLY_VERIFIED` or `REFERENCE_UNTRUSTED` (reference produced by the same actor/source it vouches for).
- Only `HASH_ONLY`: `NO_REFERENCE`.
- Reference scope narrower than the file (code pages only, metadata only): `PARTIALLY_VERIFIED`.
- Probe failed: `UNKNOWN`.

**Step 3, `content_origin`.**
- `VERIFIED_BINDING` requires (a)-(c): a signature, attestation or signed-index match that ties **these bytes** to a source identity. Source identity maps to the value: OS vendor key or platform signature -> `OS_VENDOR`; distribution's signed repo -> `REGISTERED_REPOSITORY`; third-party signed repo/tap -> `THIRD_PARTY_REPOSITORY`; Developer ID team -> `VENDOR_DIRECT`.
- `DECLARED_BY_MANAGER`: a receipt/history entry says it. Value from the declaration (e.g. receipt tap `homebrew/core` -> `REGISTERED_REPOSITORY`). Not upgraded to `VERIFIED_BINDING` without step 2 (a)-(c).
- `DECLARED_BY_WRITABLE_METADATA`: quarantine/WhereFroms/`direct_url.json`/labels -> `USER_DOWNLOAD_RECORDED` or the declared value.
- `LOCAL_BUILD`: `path+file://` cargo source, Go buildinfo with `vcs.modified`, install manifest in a build tree, `built_on` equal to this host.
- `INFERRED` is allowed only for `UNKNOWN`-adjacent hints (e.g. `LOCAL_BUILD` from a toolchain string) and never counts toward confidence.
- Nothing: `UNKNOWN` with `claim_basis=NONE`.

**Step 4, `installation_method`.** From the manager record (`installed_on_request`, `poured_from_bottle`, pkg receipt, history). Evidence that merely excludes alternatives (no receipt, quarantine present) gives `APP_BUNDLE_COPY` / `MANUAL_COPY` at `LOW` and records the missing items. No evidence: `UNKNOWN`. `SCRIPT_OR_PIPE_UNRECORDED` only with positive evidence (e.g. an installer script left a marker); otherwise `UNKNOWN`.

**Step 5, `provenance_confidence`.** Computed over the origin and ownership claims.

| Level | Definition |
|---|---|
| `UNKNOWN` | No supporting evidence for origin or ownership. |
| `LOW` | One independence group, or only `WRITABLE_METADATA`/`HEURISTIC`. |
| `MEDIUM` | Two or more independent groups agree, or one `SYSTEM_AUTHORITATIVE` record, but no reference check on the bytes. |
| `HIGH` | A `SYSTEM_AUTHORITATIVE`/`MANAGER_DECLARED` record **and** an integrity reference check of strength (a)-(d) agree, no contradiction. |
| `VERY_HIGH` | A cryptographic binding (signature/attestation) of these bytes to the source identity verified end to end, plus a consistent local record, no contradiction. |

Rules:
- C1 independence: evidence in the same `independence_group` counts once.
- C2 contradiction cap: any `contradicts` entry against origin/ownership/integrity sets `contradicted=true`, lowers by one level per independent contradiction group (floor `LOW` if there is still positive evidence, `UNKNOWN` if none), and `HIGH`/`VERY_HIGH` are impossible with `contradicted=true` (schema-enforced). Rule ids go to `cap_rule_ids` (e.g. `CAP-INTEGRITY-MODIFIED`, `CAP-ORIGIN-HOST-MISMATCH`, `CAP-OWNER-VERSION-MISMATCH`).
- C3 `MODIFIED` integrity caps at `LOW`; the origin claim remains visible as "declared" but is not trusted.
- C4 never-upgrade: confidence never rises from time, from a clean scan, from path, from name match, or from user-writable metadata appearing twice (same writer). `detection_status` does not feed confidence (a clean YARA scan is not provenance).
- C5 absence: absences lower nothing by themselves but are listed in `missing`; confidence stays at the level the positive evidence supports.
- C6 staleness: a document older than `max_age` (policy) or whose identity tuple changed is `RESULT_STALE` for detection and re-evaluated for integrity; confidence is recomputed, never carried over.
- C7 unknown is not penalized into "suspicious" and not promoted into "ok": it is its own state in any UI/report.

**Step 6, `detection_status`.** Copied from the detection pipeline for the same `sha256` (`scanned_sha256` must equal the file's current hash, otherwise `RESULT_STALE`).

Worked contradictions (see fixtures): a quarantined signed app whose `codesign --verify` fails and whose download host differs from the publisher domain ends `MODIFIED`, `LOW`, `contradicted`. A same-named cask in today's catalog is a `NAME_COLLISION_NOTE` with no weight. An unowned ELF with only a hash is `UNKNOWN`/`NO_REFERENCE`/`NOT_OWNED`.

## 6. Host-wide and fleet aggregation contract

- **File -> package -> application -> host.** Package and application documents carry `members[]` (file document ids) and derive their six fields by a documented reduction: `integrity_status` = worst member (`MODIFIED` > `UNKNOWN` > `NO_REFERENCE` > `PARTIALLY_VERIFIED` > `VERIFIED_INTACT`), `provenance_confidence` = minimum member, `package_ownership` = counts, `detection_status` = worst. Reductions report counts per value; there is no single "host score" and no "safe" total.
- **Host document** is a summary: counts per value for each of the six fields, list of `NOT_QUERYABLE` managers and the coverage state of each, the policy version, and ids of file documents. Absent managers appear as `coverage.state=DESIGNED/NOT_POSSIBLE`, never silently skipped.
- **Fleet.** The fleet receives only aggregate counts and hashes (no paths, no file contents): `{policy_version, os_family, os_version, manager coverage, counts per field value, set of SHA-256 with their six fields}` where the SHA-256 set is optional and subject to opt-in. Hash-keyed records allow "same bytes, different provenance on host A and B" detection. Fleet merging is monotone: a verdict from a host with stronger evidence does not overwrite another host's; both are kept, keyed by the evidence-bearing document.
- Idempotence: ephemeral batch ids, no persistent host identifiers by default (`host_ref` is run-scoped).
- Schema compatibility: consumers must ignore unknown evidence kinds (treat as `OTHER`) and treat unknown enum values of a field as `UNKNOWN`, never as better than `UNKNOWN`.

## 7. Privacy and security properties

- **No file contents leave the host.** Hashes and metadata only; content-bearing fields (strings, file bodies) are excluded. Paths are normalized (`~`) and the fleet export drops them.
- **No network by default.** Registry/attestation checks (bottle comparison, PyPI attestations, cosign, `npm audit signatures`) run only when the user opts in per run; `engine.network_used` and `needs_network` record it. Offline results are complete in their own right (`NOT_CHECKED` attestations).
- **Private data excluded:** shell history, the LaunchServices quarantine events database, browser history, credentials in git remote URLs (redacted), ssh config. The engine reads only the xattrs on the file itself.
- **Never execute the subject or its metadata.** Parse receipts, plists, `RECORD`, lockfiles as data; do not run `brew` formulas, `setup.py`, `postinstall`, or the binary (`binary --version` forbidden). Manager CLIs (`dpkg`, `rpm`, `pacman`, `pkgutil`, `codesign`, `spctl`, `go version -m`, `brew info`) are invoked with fixed argument vectors (no shell), a clean environment, and a timeout. Prefer parsing databases/files directly when a CLI could load user config or reach the network (`brew` may auto-update unless `HOMEBREW_NO_AUTO_UPDATE=1`; parsing the receipt JSON avoids the question).
- **Symlink and TOCTOU safety.** `lstat` first; open with `O_NOFOLLOW`; operate by file descriptor (`fstat`, hash from the same fd); record `(dev, inode, size, mtime_ns)` before and after hashing; if it changed, mark `stable_during_read=false` and retry once, else emit a warning and no integrity claim. Directory walks use `openat`/`fts` with `FTS_PHYSICAL`, never follow links out of the requested root, stay on one device unless asked, and skip special files (FIFOs, devices, sockets) and `/proc`, `/sys`, `/dev`.
- **Resource limits.** Per-file size cap for hashing (streaming, 1 MiB buffers), global bytes/sec and open-fd budgets, max entries per manager query, timeouts on every subprocess, concurrency via `engctl sched plan`, memory ceiling; on limit hit emit `SCAN_PARTIAL`/`UNKNOWN` plus the limit reached, never a partial result as complete. Archives (DMG, pkg, wheels) are not unpacked by default; if unpacked, inside a private temp dir with zip-slip/zip-bomb limits.
- **Read-only.** The engine writes only its own output; it does not change xattrs (including removing quarantine), does not run `brew update`, `apt update`, or any state-changing manager command. Test downloads go to a private temp directory.
- **Hardening of the evidence store:** documents are append-only per run; later runs link by `document_id` and history, they do not rewrite.

## 8. Experiments run on this Mac

All read-only on system, Homebrew, or Python files; the only writes were to a private temporary directory (a copy of a harmless binary, used for the xattr/codesign experiment). Home paths shown as `~`. Machine: macOS 15.7, x86_64. `rpm`, `dpkg` are not installed here, so Linux rows are not tested.

| # | Command (general form) | Returned, in general terms | What it taught |
|---|---|---|---|
| 1 | `brew --prefix`; list of `Cellar/jq/*` | `/usr/local`; keg with `INSTALL_RECEIPT.json`, `.brew/jq.rb` | Receipt lives in the keg, same account owns it |
| 2 | Read keg `INSTALL_RECEIPT.json` | `poured_from_bottle`, `installed_on_request`, `time`, `tap=homebrew/core`, `tap_git_head: null`, `changed_files` (one `.pc` file), `built_on` (macOS 14.8 builder), `runtime_dependencies`, `source.path` (a file under `~/Library/Caches/Homebrew`) | Rich install metadata, **no per-file hashes**, no tap commit for API installs |
| 3 | `brew info --json=v2 jq` | Formula/tap, installed version/time, `bottle` file list for current platform with archive sha256 | Catalog describes the bottle **archive**; not a reference for installed files |
| 4 | `otool -L` on the installed brew binary; `shasum -a 256`; `codesign -dv` | Absolute `/usr/local/...` library paths; ad hoc signature, no Team ID | Bottle pour **relocates** Mach-O, so bytes != bottle bytes; ad hoc signature gives no identity |
| 5 | Compare mtime of a plain-text file in the keg with receipt `source_modified_time` | Equal | Non-relocated files keep the bottle's build mtime, and are byte-comparable to the bottle |
| 6 | List `Caskroom/<cask>/.metadata`, read cask `INSTALL_RECEIPT.json`; `brew info --json=v2 --cask` | Receipt with `tap_git_head`, `uninstall_artifacts`; `config.json`; per-version snapshot `Casks/<cask>.json`; catalog now has a **newer version and sha256** than installed | Cask keeps the definition at install time; the live catalog must not be used as origin (R2) |
| 7 | `pkgutil --pkgs`, `--pkg-info`, `--file-info`, `--files` | 67 pkg ids; pkg-info gives version/location/install-time; `--file-info` on a Command Line Tools binary names the pkgid with mode/uid/gid; on `/usr/bin/git`, `/bin/ls`, and the brew symlink: **no owner** | System shims and sealed-volume files are not in any receipt; "no owner" there is normal, not suspicious; ownership cannot imply integrity (no digest returned) |
| 8 | `pkgutil --verify`; `lsbom` on `/var/db/receipts/<id>.bom`; `ls /var/db/receipts` | `--verify` is not an option on this macOS; the BOM for the Apple pkg was not at that path (62 entries, none for that pkg) although `pkgutil` still answered | Do not depend on BOM verification; query via `pkgutil`, treat missing BOM as `NOT_QUERYABLE` |
| 9 | Copy a binary to a private temp dir; `xattr -w com.apple.quarantine`; write a WhereFroms plist xattr; `xattr -l`; `mdls -name kMDItemWhereFroms`; append a byte; `codesign --verify` | Writes succeeded for the user; direct `xattr` read returned both values; **`mdls` returned `(null)` for the same file** (outside Spotlight index); the copy already had `com.apple.provenance`; after appending one byte, `codesign --verify` failed ("failed strict validation") | Quarantine/WhereFroms are forgeable by any user process; `mdls` is not a reliable reader; even ad hoc signatures detect post-signing modification but are re-signable |
| 10 | `xattr` listing of apps in `/Applications` | Manually installed apps (browsers, utilities, terminals): `com.apple.quarantine` still present months after first launch; the cask-installed terminal app: **no quarantine**, only `com.apple.macl`, `com.apple.provenance`; Mac App Store apps: `com.apple.appstore.*` xattrs and `Contents/_MASReceipt`; Safari: no xattrs | Absence of quarantine means nothing about origin; MAS apps have strong markers; `com.apple.macl`/`com.apple.provenance` are ubiquitous and not origin fields |
| 11 | `codesign -dv --verbose=2`, `codesign --verify --deep --strict`, `spctl --assess -vv` on a cask app, a MAS app, Safari, a manual app | Developer ID + Team ID + `Notarized Developer ID`; `Mac App Store`; `Apple System`; verify exit 0 | `spctl` `source=` is the best compact classifier of distribution channel; each is a distinct `content_origin` basis |
| 12 | `importlib.metadata`: for each dist read `INSTALLER`, `direct_url.json`, `RECORD`; re-hash every `RECORD` entry (`sha256`, urlsafe base64) in the Apple-supplied Python 3.9 site-packages | 7 dists, all `INSTALLER=pip`, all with `RECORD`, 5 with `direct_url.json`; hashes: 821 ok, 22 mismatches (21 `.py`, 1 `.pem`), 15 listed files missing | `INSTALLER=pip` does not say who ran pip (Apple's build did); `RECORD` mismatches exist in a vendor install with no tampering known: a mismatch is a contradiction to explain, not a verdict |
| 13 | `npm root -g`, `npm ls -g`, look for `.package-lock.json` | Global tree of `corepack` and `npm` with **no** hidden lockfile | Node-bundled tools have no lockfile integrity at all; coverage for global npm is `NO_REFERENCE` |
| 14 | Read `~/.cargo/.crates2.json`, `.crates.toml`, list `~/.cargo/bin` | Per-crate: name, version, source (`registry+...` or `path+file://...`), bins, features, profile, target, rustc string; no hashes, no timestamps | Source identity yes; no binary reference; `path+file://` means a local build |
| 15 | `go version -m` on a `go install`ed binary | Go version, module path and version, module `h1:` hash, `build` settings, 147 dependency lines | Rich embedded provenance of the **source**; nothing about the binary's bytes; any replacement binary can carry the same data |
| 16 | `docker images --digests`; `docker image inspect` | Repo digests, image ids, 20 layers, 8 labels; one image with `<none>` tag and a digest; `cosign`, `syft`, `gh` present but not run (they need the network) | Digest is a content identity; tags and labels are not; dangling tags lose the name |
| 17 | `git log -1 --format=%G?` on this repo and on Homebrew's checkout; `git remote -v` | `N` (no signature) and `E` (cannot be checked); remote URL uses an ssh host alias | Signature status needs a keyring; remote may hide the real host behind an alias |

## 9. Versioning and compatibility

- `schema_version` is semver: `1.x.y`. Minor: new optional fields, new enum values (consumers treat unknown enum values as `UNKNOWN`, which is never better than `UNKNOWN`); patch: description fixes. Major: removing or redefining a value. Because `UNKNOWN` is always the fallback, an old consumer can never read a new document as safer than it is.
- `engine.policy_version` is separate from the schema: the combination rules (section 5) are versioned; a policy change recomputes assessments from stored evidence (evidence is kept, verdicts are derived). Golden fixtures pin each policy version.
- Evidence `kind` is an open vocabulary with `OTHER`; adding a kind is a minor change.
- Documents are immutable; supersession is by newer `generated_at` with the same subject identity tuple; the history array carries the link.
- The vocabulary of the six fields is a contract with the UI/report layer: no field may gain a value named `SAFE`, `TRUSTED`, `OK` or `CLEAN` without a human-approved policy change.

## 10. Test plan

1. **Schema/fixture tests.** Validate the three fixtures and a corpus of generated documents against the schema (2020-12 validator). A mini-validator run during this design confirmed: the three fixtures validate; mutated copies are rejected for `VERIFIED_INTACT` without reference, `supports` on `HASH_ONLY`, a basis on `UNKNOWN` origin, value `SAFE`, `HIGH` without basis, and a quarantine xattr typed as `SYSTEM_AUTHORITATIVE`.
2. **Golden evidence tests.** For each manager, recorded raw outputs (sanitized) -> expected six-field assessment; one fixture per row of section 4 where a real sample can be made.
3. **Property tests.** (a) Adding a `contradicts` never raises confidence. (b) Adding evidence in an already-counted `independence_group` never raises confidence. (c) Removing evidence never turns `UNKNOWN`/`NO_REFERENCE` into something stronger. (d) `PATH_LOCATION` and `NAME_COLLISION_NOTE` in any amount never change any of the six fields. (e) Permuting evidence order gives identical output. (f) `HIGH`/`VERY_HIGH` imply `contradicted=false`. (g) Hash-only never yields `VERIFIED_INTACT`.
4. **Negative tests (must stay red unless handled).**
   - Same-named package present in the official repo / `apt-cache policy` / current cask, but the installed file is modified or came from elsewhere: origin must not be `REGISTERED_REPOSITORY` by name; modified -> `MODIFIED` + capped confidence.
   - Replaced binary at an owned path: `OWNED_BY_PACKAGE` with `MODIFIED` (checksum mismatch) and `contradicted`.
   - Forged quarantine/WhereFroms on a locally built binary: origin stays `DECLARED_BY_WRITABLE_METADATA`, confidence `LOW`.
   - Stripped quarantine from a downloaded app: no inference of "installed by package"; origin `UNKNOWN`.
   - Unreadable package database (permissions): `OWNERSHIP_NOT_QUERYABLE`, never `NOT_OWNED`.
   - File changed during hashing (TOCTOU), symlink swapped for a file: `stable_during_read=false`, no integrity claim.
   - Hostile receipt/lockfile (huge, deeply nested, path traversal in `RECORD`): bounded parse, no read outside the root.
   - Homebrew relocated Mach-O compared with the bottle: must yield `PARTIALLY_VERIFIED`/`NO_REFERENCE`, not `MODIFIED` and not `VERIFIED_INTACT`.
   - `pip` `RECORD` mismatch on a vendor install: `MODIFIED` vs `RECORD` but confidence not zero, reason lists `RECORD is installer-written`.
5. **Real-host sampling.** Sample N files per manager on this Mac and on one Debian, one Fedora, one Arch host (VMs/containers; read-only); a human reviews 100% of `MODIFIED` and a random 5% of `HIGH`; record precision/recall of ownership vs ground truth from the manager's own verify command. Linux rows in section 4 stay `designed` until confirmed here.
6. **Performance and resource tests** under `engctl sched plan` capacity: full host scan within the declared budget, no unbounded memory; a timeout must produce `UNKNOWN`/`SCAN_PARTIAL`, never a pass. Time is never a PASS criterion.
7. **Privacy tests.** Assert exported fleet payloads contain no paths, usernames or URLs; assert no outbound sockets when `network_used=false`.

## 11. Implementation phases

| Phase | Scope | Justification (evidence quality) |
|---|---|---|
| P0 | Schema, hasher with TOCTOU safety, evidence store, combination policy 1.0.0, golden tests | Everything else depends on the separation of the six facts |
| P1a (macOS) | Code signature + notarization + Gatekeeper source (`codesign`, `spctl`), MAS receipt, pkgutil ownership, quarantine/WhereFroms (direct xattr), Homebrew formula/cask receipts (read-only), `com.apple.provenance` as no-weight | Best evidence on macOS: cryptographic signatures and OS-authoritative sources; the weak ones (xattrs, receipts) are labeled as such |
| P1b (Linux) | dpkg ownership + md5sums, rpm ownership + digests, pacman ownership + mtree, dnf/zypper install repo | Package databases give ownership and (RPM/pacman) real per-file digests; dpkg weaker but ubiquitous |
| P2 | Python (`RECORD`, `INSTALLER`, `direct_url`), Go buildinfo, Cargo `.crates2.json`, npm lockfiles, Git state, install manifests (best-effort) | Cheap local metadata; integrity references are installer-written (`PARTIALLY_VERIFIED`) |
| P3 | Opt-in network: Homebrew bottle comparison (non-relocated files only), PyPI/npm attestations, cosign/SLSA, APT/RPM repo re-fetch | Highest assurance but needs network and trust roots |
| P4 | Flatpak, Snap, AppImage, containers | Strong where it exists (Snap assertions, OSTree), more platform surface |
| P5 | Fleet aggregation contract | After single-host semantics are stable |

## 12. Non-goals

- Deciding whether software is malicious or safe; that belongs to detection, and `SCANNED_NO_MATCH` is not a safe verdict.
- Reconstructing history before the engine's first observation, or recovering what `curl | sh` did.
- Trusting any path layout, file name, or catalog entry as origin.
- Executing, unpacking by default, or instrumenting the inspected software.
- Fixing or updating packages, removing quarantine, or changing any manager state.
- Uploading file content, shell history, or the quarantine events database.
- A single host "trust score" or a green/red badge derived from `UNKNOWN`.
- Windows support in v1.
- Supply-chain verdicts on upstream source (Homebrew's bottle vs the upstream tarball) beyond what attestations prove.

## 13. Open questions for the owner

1. May the opt-in network checks (bottle compare, attestations) ship in v1, or should v1 be strictly offline?
2. Should `com.apple.provenance` ever get a (very low) weight, or stay recorded-only as designed?
3. For dpkg without `md5sums`, is `NO_REFERENCE` acceptable to show, or should the engine offer re-download-and-compare from the signed repository?
4. Reading the LaunchServices quarantine events database would recover origin URLs for downloads; it is personal data. Allowed under any condition?
5. Minimum Linux distributions and versions for P1b, and whether Linux hosts will be tested in CI containers or on real VMs.
6. Where in the fleet is the SHA-256 set allowed to leave the host (optional telemetry, never default)?
