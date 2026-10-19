# Vendored front-end dependencies

| File | Package | Version | License | SHA-256 | Source |
|---|---|---|---|---|---|
| `mermaid-12.2.0.min.js` | mermaid | 12.2.0 | MIT (`mermaid-LICENSE.txt`) | `a8a6a6f805b074a8261a2825c86f99c8054acb3b35f50bb7e24a4f9f2c3c3b9f` | `npm pack mermaid@12.2.0` (npm verifies the registry integrity `sha512-w7nr/SFrLO7BaVTs3dQTvYSV6nYSBj0Yy9DjBhsIJtAcHqRzXSq4Pg32ujHZ/AdWsAMNEvvhbm5dt9E2tOiHzw==`), file `package/dist/mermaid.min.js` |

Loaded by the documentation pages with a Subresource Integrity attribute (`sha256-qKam+AWwdKgmGiglyG+ZyAVKyzs19Qu34kpPnyw8O58=`), served from this site, never from a CDN. 12.2.0 replaces 10.9.8 (which replaced 10.9.3, affected by eight published Mermaid advisories). 10.9.8 fixed those but still bundles DOMPurify 3.4.2, which has eleven published advisories (hooks, `IN_PLACE`, `setConfig`, Trusted Types); 12.2.0 bundles DOMPurify 3.4.12, which fixes every moderate one; two LOW advisories about `IN_PLACE` mode (GHSA-6688-9rhm-gjv2, fixed only in 3.4.16, and GHSA-x4vx-rjvf-j5p4, no fix yet) remain. None of these code paths is reachable here (the diagrams are this repository's own text, Mermaid runs in `strict` mode, nothing from a visitor reaches it), but the version with the fewest known advisories that renders the documentation is the one kept. The cost is about 575 KB more transfer (gzip 1.57 MB against 0.99 MB) on the documentation pages that have diagrams.

To update: pack the new version, replace the file, update this table and `MERMAID_VERSION` in `scripts/build_docs.py`; `tests/test_docs.py` checks that the hash, the SRI value and the version agree.
