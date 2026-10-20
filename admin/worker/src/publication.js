// Evidence that a release is really public, taken from GitHub by the Worker itself (never from what a request says it published).
import { RELEASE_TAG, sha256Hex, verifyManifest } from './core.js';

const MAX_MANIFEST_BYTES = 8_000_000;
const stop = () => (typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(10_000) : undefined);
const fail = (status, error) => ({ ok: false, status, error });

/** The public release `tag` (the latest public release when `tag` is null): its manifest.json downloaded, checked against the digest GitHub reports for the
 *  asset when it reports one, and verified to be well formed with a rules_root that matches its own file list. A draft is not public: GitHub does not show it
 *  to an anonymous caller and does not serve its assets. This does not verify the Sigstore signatures; publish.yml verifies them before the release becomes
 *  public and site.yml verifies the public release again. */
export async function fetchPublication(env, deps, tag = null) {
  if (tag !== null && !RELEASE_TAG.test(tag)) return fail(400, 'not a release tag');
  const api = `${env.GITHUB_API || 'https://api.github.com'}/repos/${env.REPO}`, headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'macguard-admin' };
  let rel = null;
  try {
    const r = await deps.fetch(tag ? `${api}/releases/tags/${tag}` : `${api}/releases/latest`, { headers, signal: stop() });
    if (r.status === 404) return fail(409, 'there is no public release with that tag');
    if (r.ok) rel = await r.json(); else if (!tag) return fail(502, `GitHub answered ${r.status}`);
  } catch { if (!tag) return fail(502, 'GitHub could not be reached'); }
  let url, digest = null, level = 'api';
  if (rel) {
    if (rel.draft || !rel.published_at) return fail(409, 'the release is a draft, not a public release');
    if (typeof rel.tag_name !== 'string' || !RELEASE_TAG.test(rel.tag_name) || (tag && rel.tag_name !== tag)) return fail(409, 'the release does not carry the expected tag');
    tag = rel.tag_name;
    const asset = (rel.assets || []).find((a) => a && a.name === 'manifest.json');
    if (!asset) return fail(422, 'the release has no manifest.json');
    url = String(asset.browser_download_url || ''); digest = typeof asset.digest === 'string' ? asset.digest : null;
    if (!url.startsWith(`https://github.com/${env.REPO}/releases/download/${tag}/`)) return fail(422, 'the manifest does not live where the release says');
  } else {   // the API is unreachable for an explicit tag: a public download is itself the proof that the release is public (assets of a draft are not served)
    url = `https://github.com/${env.REPO}/releases/download/${tag}/manifest.json`; level = 'download';
  }
  let bytes;
  try {
    const res = await deps.fetch(url, { headers: { 'User-Agent': 'macguard-admin' }, signal: stop() });
    if (res.status === 404) return fail(409, 'the manifest of that release is not publicly downloadable');
    if (!res.ok) return fail(502, `the manifest download answered ${res.status}`);
    bytes = new Uint8Array(await res.arrayBuffer());
  } catch { return fail(502, 'the manifest could not be downloaded'); }
  if (bytes.length > MAX_MANIFEST_BYTES) return fail(422, 'the manifest is too large');
  const manifestSha = await sha256Hex(bytes);
  if (digest && /^sha256:[0-9a-f]{64}$/.test(digest) && digest.slice(7) !== manifestSha) return fail(422, 'the downloaded manifest does not match the digest GitHub reports for the asset');
  const v = await verifyManifest(bytes); if (!v.ok) return fail(422, v.error);
  return { ok: true, tag, release: { id: rel ? rel.id ?? null : null, published_at: rel ? rel.published_at : null, evidence: level, asset_digest_checked: !!(digest && level === 'api') }, manifest_sha256: manifestSha, rules_root: v.rules_root, files: v.files };
}
