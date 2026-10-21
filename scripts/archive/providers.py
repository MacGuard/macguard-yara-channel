"""Storage providers behind one write-once interface.

LocalDirectory  files in a directory (tests, and a local mirror).
S3Cli           any S3-compatible bucket (Cloudflare R2, Backblaze B2, Scaleway) through a configurable CLI (`rclone` or `aws`).

Rules shared by every provider: an object is written once (same bytes again is a no-op, different bytes under the same key is ObjectConflict); nothing is ever
deleted or overwritten; every external call has a timeout; credentials are never read, logged or put on a command line here (the CLI finds them in its own
environment or config)."""
import abc, os, pathlib, subprocess, tempfile

TIMEOUT = 120


class ProviderError(Exception): pass
class MissingObject(ProviderError): pass
class ObjectConflict(ProviderError): pass


def check_key(key: str) -> str:
    parts = key.split('/')
    if not key or key.startswith('/') or any(p in ('', '.', '..') for p in parts) or '\\' in key or '\0' in key: raise ProviderError(f'unsafe object key: {key!r}')
    return key


class Provider(abc.ABC):
    name = 'provider'
    @abc.abstractmethod
    def _put_new(self, key: str, data: bytes) -> bool:
        """Create `key` with `data` only if absent. True if created, False if it already existed. Never overwrites."""
    @abc.abstractmethod
    def get(self, key: str) -> bytes: """Bytes of `key`; MissingObject if absent."""
    @abc.abstractmethod
    def exists(self, key: str) -> bool: ...
    @abc.abstractmethod
    def list(self, prefix: str = '') -> list: """Sorted keys starting with `prefix`."""

    def put_if_absent(self, key: str, data: bytes) -> str:
        check_key(key)
        if self._put_new(key, data): return 'created'
        if self.get(key) == data: return 'exists-identical'
        raise ObjectConflict(f'{self.name}: {key} already exists with different bytes (objects are write-once)')


class LocalDirectory(Provider):
    def __init__(self, root, name='local'):
        self.root, self.name = pathlib.Path(root), name
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key): return self.root / check_key(key)

    def _put_new(self, key, data):
        p = self._path(key); p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix='.part-')
        try:
            with os.fdopen(fd, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
            os.chmod(tmp, 0o444)
            try: os.link(tmp, p)       # atomic create-if-absent: two concurrent writers cannot both win
            except FileExistsError: return False
            return True
        finally:
            try: os.unlink(tmp)
            except FileNotFoundError: pass

    def get(self, key):
        try: return self._path(key).read_bytes()
        except FileNotFoundError: raise MissingObject(f'{self.name}: {key} is not there')

    def exists(self, key): return self._path(key).is_file()

    def list(self, prefix=''):
        out = []
        for p in self.root.rglob('*'):
            if p.is_file() and not p.name.startswith('.part-'):
                k = p.relative_to(self.root).as_posix()
                if k.startswith(prefix): out.append(k)
        return sorted(out)


class S3Cli(Provider):
    """`cli` is the argv prefix of the tool, e.g. ['rclone'] or ['aws', '--endpoint-url', 'https://s3.example']. `kind` is 'rclone' or 'aws'.
    `remote` is the rclone remote name (kind 'rclone'); `bucket` the bucket. Credentials live in the tool's own environment or config, never here."""
    def __init__(self, name, kind, cli, bucket, remote=None, timeout=TIMEOUT, env=None):
        if kind not in ('rclone', 'aws'): raise ProviderError('kind must be rclone or aws')
        if kind == 'rclone' and not remote: raise ProviderError('rclone needs a remote name')
        self.name, self.kind, self.cli, self.bucket, self.remote, self.timeout, self.env = name, kind, list(cli), bucket, remote, timeout, env

    def _run(self, args, ok=(0,)):
        try: r = subprocess.run(self.cli + args, capture_output=True, timeout=self.timeout, env=self.env)
        except subprocess.TimeoutExpired: raise ProviderError(f'{self.name}: {self.kind} timed out after {self.timeout}s')
        except OSError as e: raise ProviderError(f'{self.name}: cannot run {self.cli[0]}: {e}')
        if r.returncode not in ok: raise ProviderError(f'{self.name}: {self.kind} failed ({r.returncode}): {r.stderr.decode("utf-8", "replace")[:300].strip()}')
        return r

    def _url(self, key): return f'{self.remote}:{self.bucket}/{check_key(key)}' if self.kind == 'rclone' else f's3://{self.bucket}/{check_key(key)}'

    def exists(self, key):
        if self.kind == 'rclone': return bool(self._run(['lsf', self._url(key)], ok=(0, 3)).stdout.strip())
        r = self._run(['s3api', 'head-object', '--bucket', self.bucket, '--key', key], ok=(0, 254, 255))
        return r.returncode == 0

    def _put_new(self, key, data):
        if self.exists(key): return False
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, 'object'); pathlib.Path(src).write_bytes(data)
            if self.kind == 'rclone': self._run(['copyto', '--immutable', src, self._url(key)])
            else: self._run(['s3api', 'put-object', '--bucket', self.bucket, '--key', key, '--body', src, '--if-none-match', '*'])
        return True

    def get(self, key):
        if not self.exists(key): raise MissingObject(f'{self.name}: {key} is not there')
        with tempfile.TemporaryDirectory() as d:
            dst = os.path.join(d, 'object')
            if self.kind == 'rclone': self._run(['copyto', self._url(key), dst])
            else: self._run(['s3', 'cp', self._url(key), dst, '--only-show-errors'])
            return pathlib.Path(dst).read_bytes()

    def list(self, prefix=''):
        if self.kind == 'rclone': out = self._run(['lsf', '-R', '--files-only', f'{self.remote}:{self.bucket}']).stdout.decode().split('\n')
        else: out = [l.split(None, 3)[-1] for l in self._run(['s3', 'ls', f's3://{self.bucket}/', '--recursive']).stdout.decode().split('\n') if l.strip()]
        return sorted(k for k in out if k and k.startswith(prefix))
