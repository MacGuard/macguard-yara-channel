// AWS Signature V4 query-string presigning (what S3-compatible stores, R2 included, accept). Verified against the example published in the AWS documentation.
import { bytes, hex, hmac, sha256Hex } from './util.js';
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const encPath = (p) => p.split('/').map(enc).join('/');
export async function presignGet({ accessKeyId, secretAccessKey, region, host, path, expires, now, service = 's3' }) {
  if (!(expires >= 1 && expires <= 604800)) throw new Error('expires must be 1..604800 seconds');
  const amz = now.toISOString().replace(/[-:]|\.\d{3}/g, ''), date = amz.slice(0, 8), scope = `${date}/${region}/${service}/aws4_request`;
  const q = { 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': `${accessKeyId}/${scope}`, 'X-Amz-Date': amz, 'X-Amz-Expires': String(expires), 'X-Amz-SignedHeaders': 'host' };
  const query = Object.keys(q).sort().map((k) => `${enc(k)}=${enc(q[k])}`).join('&');
  const canonical = ['GET', encPath(path), query, `host:${host}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const sts = ['AWS4-HMAC-SHA256', amz, scope, await sha256Hex(canonical)].join('\n');
  let k = await hmac(bytes('AWS4' + secretAccessKey), date); for (const part of [region, service, 'aws4_request']) k = await hmac(k, part);
  return `https://${host}${encPath(path)}?${query}&X-Amz-Signature=${hex(await hmac(k, sts))}`;
}
