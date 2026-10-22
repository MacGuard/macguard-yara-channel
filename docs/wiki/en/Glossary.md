# Glossary

[Home](EN-Home) · [YARA Channel](EN-YARA-Channel) · [Verify a release](EN-YARA-Verify) · [Limits](EN-YARA-Limits) · [Contribute](EN-Contribute)

## In 30 seconds

Every technical word used in this wiki, in the same order and with the same wording as the pages that explain it. Each row gives a plain version, a precise version and the page to read next. If a row and its page ever disagree, the page wins and the row is a bug worth reporting. {{ev:EV-YC-80}}

## Glossary

| Term | Plain version | Precise version | Where it is explained |
|---|---|---|---|
| YARA | A way of writing "look for these words or bytes inside a file" so a computer can do the searching. | A language for describing patterns of files plus a program that searches for them; its documentation describes it as aimed at (but not limited to) helping malware researchers identify and classify samples. | [Technology: YARA](EN-Tech-YARA) |
| Rule | A "wanted poster": a file with this phrase and this size is worth a second look. | A YARA rule inside a `.yar`/`.yara` file; the channel classifies each rule file as accepted, quarantined or rejected, with reasons. A match does not prove danger. | [YARA Channel](EN-YARA-Channel) |
| YARA-X | A newer engine for the same language. | VirusTotal's re-incarnation of YARA written in Rust. In this project `VirusTotal/yara-x` is an entry of kind `engine` in `config/sources.json`; it supplies no rules and is not used for validation. | [Technology: YARA](EN-Tech-YARA) |
| Rule source | The place the rules are collected from; the channel writes none itself. | One of two public repositories, `Neo23x0/signature-base` and `Yara-Rules/rules`; each release records repository, commit and license-check result. Third-party rules keep their own licenses; the project claims no copyright over them. | [Sources](EN-YARA-Sources) |
| Hash | A fingerprint of a file: change one letter and the fingerprint changes completely. | A SHA-256 digest; the signed manifest lists the SHA-256 of every file in a release. | [Verify a release](EN-YARA-Verify) |
| Digital signature | A seal that says who sent something and whether it was changed on the way. | A cryptographic signature checked against an identity; it shows the signer's identity and the integrity of the signed bytes, not who wrote the content nor that it is good. | [Technology: Sigstore](EN-Tech-Sigstore) |
| Sigstore | A public service that gives signers a seal valid for a few minutes and keeps a public record of its use. | An open source signing project (Fulcio certificate authority, Rekor transparency log, `cosign` client) used here to check that `publish.yml` signed a release. | [Technology: Sigstore](EN-Tech-Sigstore) |
| Keyless signing | Signing without keeping a secret key lying around. | The key pair is ephemeral and discarded after signing; GitHub issues an OIDC token naming the workflow and Fulcio binds it to a short-lived certificate; verification relies on the log and checks identity and issuer. | [Technology: Sigstore](EN-Tech-Sigstore) |
| Manifest | The delivery note: the list of everything in a package. | `manifest.json`, signed with Sigstore, giving the SHA-256 of every file plus `sources`, `rules_root` and the log size and root. | [Publishing and signing](EN-YARA-Publishing) |
| Bundle | A package. The word has two meanings in this wiki. | (1) The rules package `rules-release.tar.gz`. (2) The `.sigstore.json` file holding a signature, its certificate and the log record, used by `cosign verify-blob --bundle`. | [Publishing and signing](EN-YARA-Publishing) |
| Release | One complete delivery of all the approved rules. | A complete package of rules plus its manifest, checkpoint and signature bundles, published by `publish.yml`. | [Publishing and signing](EN-YARA-Publishing) |
| Transparency log | A diary where lines are only ever added, never changed or deleted. | An append-only public log (`logs/log.jsonl`, one leaf per line) whose growth can be verified with Merkle proofs. | [Transparency log](EN-YARA-Transparency) |
| Checkpoint | A signed snapshot of the diary at one moment. | `checkpoint.txt`: three lines with origin, number of entries and root, signed with Sigstore; the manifest repeats the same size and root. | [Transparency log](EN-YARA-Transparency) |
| Merkle tree | A way to squeeze a long list into one number that changes if anything in the list changes. | A hash tree (RFC 6962 construction): leaf = SHA-256(`0x00` + data), node = SHA-256(`0x01` + left + right); implemented in `scripts/tlog.py`. | [Technology: Merkle](EN-Tech-Merkle) |
| rules_root | The single number that stands for the exact set of rule files. | The Merkle root whose leaves are the path plus hash of each rule file, sorted by path. | [Technology: Merkle](EN-Tech-Merkle) |
| Inclusion proof | A short proof that one item really is in the list. | A path of hashes, of the order of log2(n) entries, that rebuilds the signed root from one leaf. | [Technology: Merkle](EN-Tech-Merkle) |
| Consistency proof | A short proof that today's list only added things to yesterday's. | A set of hashes showing that an older tree is a prefix of a newer one, so history was not rewritten. | [Technology: Merkle](EN-Tech-Merkle) |
| Quarantine | A waiting room for rules that did not pass the checks. | Rule files that are not published: rejected, blocked or pending review; a reviewer may approve or reject only the pending ones and the file is validated again afterwards. | [Rule quarantine](EN-YARA-Quarantine) |
| Review panel | The screen where a person decides about quarantined rules. | A private review service; roles limit what each person may decide, and every decision is written to a hash-chained record. | [Rule quarantine](EN-YARA-Quarantine) |
| False positive / false negative | The alarm rings for something innocent, or stays silent for something bad. | A rule that matches a benign file, or one that misses a malicious file. The channel measures and filters but cannot promise there are none of either. | [Limits](EN-YARA-Limits) |
| S3 and bucket | A common way of talking to cloud storage, where files live in "buckets". | The S3-compatible object API that many providers implement; the planned archive uses one bucket per provider. | [Technology: S3 backups](EN-Tech-S3-Backups) |
| Versioning | Keeping old copies instead of overwriting them. | A bucket feature that keeps previous versions of an object; required for Object Lock. | [Technology: S3 backups](EN-Tech-S3-Backups) |
| Object Lock | A lock that stops a stored file being deleted or replaced for a set time. | A retention feature that prevents deleting or overwriting a version during a retention period, in governance or compliance mode. | [Technology: S3 backups](EN-Tech-S3-Backups) |
| Governance mode | A lock that someone with the master key can still open. | Object Lock mode where an identity with the right permission can bypass the lock; it does not stop a compromised authorized identity. | [Historical archive](EN-YARA-Archive) |
| Compliance mode | A lock that nobody can open until time is up. | Object Lock mode that nobody can remove during retention; it is irreversible, so an upload mistake could not be withdrawn. Not enabled in this project. | [Historical archive](EN-YARA-Archive) |
| Historical archive | A planned extra copy of every release in three places. | A three-provider archive with versioning and Object Lock. It is planned: it is not operational and no real restore has been tested. | [Historical archive](EN-YARA-Archive) |
| Code signing | The developer puts a seal on their app. | A signature over the app that says who signed it and lets macOS tell whether it changed afterwards. | [Technology: code signing](EN-Tech-CodeSigning) |
| Notarization | Apple runs an automatic check on the app and hands back a ticket. | An automatic Apple check (`xcrun notarytool`) whose ticket is stapled to the app; it is not a guarantee that there is no malware. | [Technology: code signing](EN-Tech-CodeSigning) |
| Gatekeeper | The doorman of macOS who looks at the seal and the ticket of downloaded apps. | The macOS component that, when you open something downloaded, checks the signature and notarization and asks for your approval. | [Technology: code signing](EN-Tech-CodeSigning) |
| Entitlement | A special permission that Apple gives a developer for risky powers. | A restricted capability granted to a developer account, needed for example for Endpoint Security and Network Extension. | [Technology: Network Extension](EN-Tech-NetworkExtension) |
| Endpoint Security | A guard the system asks "may I let this through?". | An Apple framework that delivers notify and authorization (AUTH) events about what happens on the system; AUTH events must be answered allow or deny within a deadline. | [Technology: Endpoint Security](EN-Tech-EndpointSecurity) |
| Network Extension | The guard post that lets a program watch and control other apps' network traffic. | Apple's framework to filter connections, proxy DNS or create a VPN; it needs an entitlement. | [Technology: Network Extension](EN-Tech-NetworkExtension) |
| DriverKit | A way to write hardware drivers that do not run in the system's core. | Apple's framework for drivers that run outside the kernel as separate programs, so a failing driver does not take the Mac down. | [Technology: DriverKit](EN-Tech-DriverKit) |

## Limits

The plain column simplifies on purpose and never promises detection of everything. Terms about Apple frameworks describe what the wiki pages say, not every detail of Apple's documentation. Statuses (operational, planned) live on the linked pages and in the evidence matrix, not here.
