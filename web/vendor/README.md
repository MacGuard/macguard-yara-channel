# Vendored front-end dependencies

| File | Package | Version | License | SHA-256 | Source |
|---|---|---|---|---|---|
| `mermaid-10.9.8.min.js` | mermaid | 10.9.8 | MIT (`mermaid-LICENSE.txt`) | `8d607d7ef1d077a8aa202e18e62212bfa992c68bfeabc5cf45d51a128fe6675d` | `npm pack mermaid@10.9.8` (npm verifies the registry integrity `sha512-gmIhmkmD/3DL5lErDV71E/cFUkEbBW4VTFpsJH1HSYjeBICRKOoc4AZem+RNz/FhhCXKBMZiD75bIfBlb2A4yA==`), file `package/dist/mermaid.min.js` |

Loaded by the documentation pages with a Subresource Integrity attribute (`sha256-jWB9fvHQd6iqIC4Y5iISv6mSxov+q8XPRdUaEo/mZ10=`), served from this site, never from a CDN. 10.9.8 replaces 10.9.3 because 10.9.3 is affected by eight published advisories (GHSA-7rqq-prvp-x9jh, GHSA-6m6c-36f7-fhxh, GHSA-87f9-hvmw-gh4p, GHSA-ghcm-xqfw-q4vr, GHSA-xcj9-5m2h-648r, GHSA-2v8p-3f2j-5mp7, GHSA-6x64-9x62-f2gx, GHSA-c4c3-pg64-4m4v), all fixed in 10.9.8. The diagrams are this repository's own text and Mermaid runs in `strict` mode, so none was exploitable here, but a known-vulnerable copy is not kept.

To update: pack the new version, replace the file, update this table and `MERMAID_VERSION` in `scripts/build_docs.py`; `tests/test_docs.py` checks that the hash, the SRI value and the version agree.
