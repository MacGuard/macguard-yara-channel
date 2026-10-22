# Installing mgctl / Instalar mgctl

The command you get is always `mgctl --version`. The package name may differ (`macguard-mgctl`). No step needs root unless you choose a system prefix.

El comando resultante es siempre `mgctl --version`. El nombre del paquete puede diferir (`macguard-mgctl`). Ningún paso necesita root salvo que elijas un prefijo del sistema.

## Name check (done 2026-10-22) / Comprobación de nombres

| Where | `mgctl` | `mg` |
|---|---|---|
| Homebrew formulae and casks (formulae.brew.sh API) | no formula, no cask | **taken** (the mg editor) |
| PyPI | no project | not checked |
| Debian source packages (sources.debian.org search) | none | package `mg` exists |
| macOS | not present | **`/usr/bin/mg` exists** on a default install |
| GitHub | unrelated repositories only, no package | n/a |

Other distributions (Fedora, Arch, Alpine, Ubuntu PPAs, Nix) were **not** checked: do it before publishing a package there. This is why `mg` is only an opt-in alias.

## 1. Manual, verifiable install (works today)

```bash
python3 pkg/make_dist.py --out dist/          # from a checkout; produces mgctl-0.1.0.tar.gz and SHA256SUMS
cd dist && shasum -a 256 -c SHA256SUMS        # Linux: sha256sum -c SHA256SUMS
tar xzf mgctl-0.1.0.tar.gz && cd mgctl-0.1.0
./install.sh install                          # prefix: ~/.local   (or --prefix /absolute/dir)
mgctl --version
```

The archive is deterministic (same inputs, same bytes). Signing is separate and not done here: `cosign sign-blob --bundle SHA256SUMS.sigstore.json SHA256SUMS` by the publisher, and `cosign verify-blob` by you, with the identity the publisher announces.

Remove it with `./install.sh uninstall` (same prefix). The installer refuses to replace anything at `PREFIX/bin/mgctl` that it did not create, and it never creates `mg`.

## 2. Debian / Ubuntu (.deb)

```bash
python3 pkg/make_deb.py --out dist/           # builds macguard-mgctl_0.1.0_all.deb in pure Python
sudo dpkg -i dist/macguard-mgctl_0.1.0_all.deb
```

The package contains `/usr/bin/mgctl` (a link) and `/usr/lib/mgctl/`; it has no maintainer scripts and does not ship `mg`. **Not verified on a real Debian/Ubuntu system** (no `dpkg` on the build machine): run `dpkg-deb --info`, `dpkg-deb --contents` and `lintian` there first. On Linux only the `hash` check and `evidence verify` work today; the Installer Auditor engine is macOS-only.

## 2b. Fedora / RHEL (RPM)

`pkg/rpm/macguard-mgctl.spec` is a **template** (same layout as the DEB, no `mg`). `rpmbuild` is not available on the build machine, so it has not been built or tested: do `rpmbuild -ba` and `rpm -qlp` on a real Fedora/RHEL system, and decide the licence field.

## 3. Homebrew (macOS and Linux)

`pkg/homebrew/macguard-mgctl.rb` is a **template** for a tap: it needs a published source archive URL and its SHA-256 from `SHA256SUMS`, and a licence decision. It installs only `mgctl`. Not submitted anywhere and not audited with `brew audit` (that needs a tap).

Homebrew also works on Linux, and DEB/RPM are not alternatives to it: they can coexist, but each installs a command called `mgctl`, so the first one on `PATH` wins. `mgctl doctor` lists every `mgctl` it finds and warns when there are several different installs. Pick one per machine.

## 3b. Standalone signed binaries

Not built. `mgctl` is Python (3.9+, standard library only); a self-contained, signed binary would need a packaging tool and a signing identity, and the first one is not chosen. Until then the verifiable forms are the deterministic archive plus its `SHA256SUMS` (section 1) and, once the owner authorises a publishing workflow, a Sigstore signature over `SHA256SUMS`.

## 4. The Installer Auditor engine

`scan`, `audit file` (integrity, yara) and `intelligence` need `macguard-audit` on macOS: build it from `DMGTrustAuditor/DMGTrustAuditor` (`xcodegen generate && xcodebuild -scheme macguard-audit build`) and put it next to `mgctl`, on `PATH`, or set `MGCTL_AUDIT_BIN`. Without the bundled YARA engine (`Scripts/build-yara-engine.sh`) the YARA check reports `unavailable`.

## 5. The optional `mg` alias

Never part of installation. See `mgctl alias --help` and `mgctl.md`. To remove it: `mgctl alias disable`.
