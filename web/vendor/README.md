# Vendored front-end dependencies

| File | Package | Version | License | SHA-256 | Source |
|---|---|---|---|---|---|
| `mermaid-10.9.3.min.js` | mermaid | 10.9.3 | MIT (`mermaid-LICENSE.txt`) | `5a8ec91820bd55afef049068489369910e5d6ce70c8103952f27e29d3e76e8bc` | `npm pack mermaid@10.9.3` (npm verifies the registry integrity `sha512-V80X1isSEvAewIL3xhmz/rVmc27CVljcsbWxkxlWJWY/1kQa4XOABqpDl2qQLGKzpKm6WbTfUEKImBlUfFYArw==`), file `package/dist/mermaid.min.js` |

Loaded by the documentation pages with a Subresource Integrity attribute (`sha256-Wo7JGCC9Va/vBJBoSJNpkQ5dbOcMgQOVLyfinT526Lw=`), served from this site, never from a CDN. To update: pack the new version, replace the file, update this table and `MERMAID_VERSION` in `scripts/build_docs.py`; `tests/test_docs.py` checks that the hash, the SRI value and the version agree.
