"""Synthetic negative tests of one provider's write-once protection (run by the owner, never by the pipeline).

Writes only tiny synthetic objects under `selftest/<utc>-<random>/`; touches nothing else; never enables publishing, never sets Compliance.
Credentials come from the environment of the process (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, typed by the owner with `read -rs`), are handed to the `aws` CLI
only through its environment, and are never printed. Each check says PASS only when the protection really held; a forbidden action that succeeds is a FAIL.

  --role write : upload + read back + SHA-256, overwrite attempt, delete-of-version attempt, retention-shortening attempt
  --role read  : read back, and upload / delete attempts that must be refused
Objects of a locked bucket cannot be removed afterwards (30-day test retention): that is expected, the payload is a few bytes."""
import argparse, hashlib, json, os, secrets, subprocess, sys, tempfile, time

PAYLOAD = b'macguard synthetic self-test object, not real data\n'


def sha(b): return hashlib.sha256(b).hexdigest()


class Aws:
    def __init__(self, endpoint, region, bucket, cli=('aws',), timeout=60):
        self.base, self.bucket, self.timeout = list(cli) + ['--endpoint-url', endpoint, '--region', region, '--output', 'json'], bucket, timeout

    def run(self, *args):
        try: r = subprocess.run(self.base + list(args), capture_output=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as e: return 255, '', str(e)[:200]
        return r.returncode, r.stdout.decode('utf-8', 'replace'), r.stderr.decode('utf-8', 'replace')[:300]

    def put(self, key, data):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'o'); open(p, 'wb').write(data)
            rc, out, err = self.run('s3api', 'put-object', '--bucket', self.bucket, '--key', key, '--body', p)
        try: vid = json.loads(out).get('VersionId') if rc == 0 and out.strip() else None
        except ValueError: vid = None
        return rc, vid, err

    def get(self, key, version=None):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'o')
            extra = ['--version-id', version] if version else []
            rc, _, err = self.run('s3api', 'get-object', '--bucket', self.bucket, '--key', key, *extra, p)
            return rc, (open(p, 'rb').read() if rc == 0 and os.path.exists(p) else None), err

    def delete_version(self, key, version): return self.run('s3api', 'delete-object', '--bucket', self.bucket, '--key', key, '--version-id', version)

    def shorten_retention(self, key, version):
        until = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 60))
        return self.run('s3api', 'put-object-retention', '--bucket', self.bucket, '--key', key, '--version-id', version, '--retention', f'Mode=GOVERNANCE,RetainUntilDate={until}')


def run_checks(api, role, prefix):
    res = []
    def add(name, ok, detail=''): res.append({'check': name, 'result': 'PASS' if ok else 'FAIL', 'detail': detail})
    key = f'{prefix}object-1'
    if role == 'write':
        rc, vid, err = api.put(key, PAYLOAD); add('upload', rc == 0, err)
        rc, data, err = api.get(key, vid); add('read back and SHA-256', rc == 0 and data is not None and sha(data) == sha(PAYLOAD), err)
        # a versioned bucket turns an overwrite into a NEW version: what must hold is that the original version stays readable and unchanged (tested on its own key, so object-1 stays pristine for the read role)
        okey = f'{prefix}object-2'; _, ovid, _ = api.put(okey, PAYLOAD); api.put(okey, PAYLOAD + b'changed\n')
        rc, data, err = api.get(okey, ovid) if ovid else (1, None, 'no version id returned: versioning/lock not active?')
        add('overwrite does not alter the original version', rc == 0 and data is not None and sha(data) == sha(PAYLOAD), 'original version intact' if rc == 0 else err)
        if vid: rc, _, err = api.delete_version(key, vid); add('delete of the locked version is refused', rc != 0, 'DELETE SUCCEEDED' if rc == 0 else err)
        else: add('delete of the locked version is refused', False, 'no version id to test')
        if vid: rc, _, err = api.shorten_retention(key, vid); add('shortening the retention is refused', rc != 0, 'RETENTION CHANGED' if rc == 0 else err)
        else: add('shortening the retention is refused', False, 'no version id to test')
    else:
        want = os.environ.get('SELFTEST_EXISTING_KEY')
        if not want: add('read an object written by the write role', False, 'set SELFTEST_EXISTING_KEY to a key written by the write run'); return res
        rc, data, err = api.get(want); add('read and SHA-256', rc == 0 and data is not None and sha(data) == sha(PAYLOAD), err)
        rc, _, err = api.put(f'{prefix}read-role-must-fail', PAYLOAD); add('upload is refused for the read role', rc != 0, 'UPLOAD SUCCEEDED' if rc == 0 else err)
        rc, _, err = api.run('s3api', 'delete-object', '--bucket', api.bucket, '--key', want); add('delete is refused for the read role', rc != 0, 'DELETE SUCCEEDED' if rc == 0 else err)
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or '').split('\n')[0])
    ap.add_argument('--role', choices=('write', 'read'), required=True)
    ap.add_argument('--provider', required=True)
    ap.add_argument('--confirm-synthetic-only', action='store_true', help='required: this writes tiny synthetic objects under selftest/')
    a = ap.parse_args(argv)
    if not a.confirm_synthetic_only: print('refusing: pass --confirm-synthetic-only', file=sys.stderr); return 2
    need = [v for v in ('ARCHIVE_BUCKET', 'ARCHIVE_ENDPOINT', 'ARCHIVE_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY') if not os.environ.get(v)]
    if need: print('missing environment: ' + ', '.join(need), file=sys.stderr); return 2
    prefix = f'selftest/{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}-{secrets.token_hex(4)}/'
    api = Aws(os.environ['ARCHIVE_ENDPOINT'], os.environ['ARCHIVE_REGION'], os.environ['ARCHIVE_BUCKET'])
    res = run_checks(api, a.role, prefix)
    ok = all(r['result'] == 'PASS' for r in res)
    print(json.dumps({'provider': a.provider, 'role': a.role, 'prefix': prefix, 'ok': ok, 'checks': res}, indent=1))
    return 0 if ok else 1


if __name__ == '__main__': sys.exit(main())
