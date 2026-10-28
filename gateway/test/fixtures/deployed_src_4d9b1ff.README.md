# deployed_src_4d9b1ff — the gateway code that was deployed before migrations 0001-0003

**Test-only.** It is executed by `gateway/test/staging_rehearsal.test.js` (rollback step: "the previous code still works on the migrated schema"). It is never bundled or deployed: wrangler builds from `gateway/src`.

- `deployed_src_4d9b1ff.tar.gz` is `git archive --format=tar 4d9b1ff gateway/src | gzip -n -9` (byte-reproducible; SHA-256 `5b0fe7f7609505a3686278dba59faf6b2050f15643fc9b60d0339d14d54f9412`, pinned in the test).
- `deployed_src_4d9b1ff.blobs.txt` lists the git blob id of each of the 29 files (`git ls-tree -r 4d9b1ff -- gateway/src`). The test recomputes each blob id from the extracted file, so a copy that is not verbatim fails without needing git.
- Commit `4d9b1ff` exists only on local branches (24 unpublished commits behind it); it is not in `main` or any remote history. This is why the code is frozen here instead of read with `git archive` at test time.
- Reviewed for secrets before committing: no key, token, e-mail or account identifier; the only hosts are api.github.com, docs.github.com and api.stripe.com.

Verify on a machine that has the commit:
```sh
git archive --format=tar 4d9b1ff gateway/src | gzip -n -9 | shasum -a 256     # must equal 5b0fe7f7609505a3686278dba59faf6b2050f15643fc9b60d0339d14d54f9412
git ls-tree -r 4d9b1ff -- gateway/src | awk '{print $3"  "$4}' | diff - gateway/test/fixtures/deployed_src_4d9b1ff.blobs.txt
```
