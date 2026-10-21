"""Envelope encryption for private data BEFORE it leaves the archiving process, through the `age` CLI (https://age-encryption.org).

Encryption needs only PUBLIC recipients (`age1...`); decryption needs an identity file that the archiving process never holds. Data goes through stdin/stdout
pipes (nothing private is written to disk by this module); keys never appear on a command line except public recipients; every call has a timeout."""
import re, subprocess

TIMEOUT = 120
RECIPIENT = re.compile(r'^age1[0-9a-z]{20,}$')


class CryptoError(Exception): pass


class AgeCli:
    """`binary` is the argv prefix for age, e.g. ['age'] (tests pass a fake). `recipients` are public keys; at least one is required, and two or more are
    expected in production (archive key + independent custodian key)."""
    def __init__(self, recipients, binary=('age',), timeout=TIMEOUT):
        rs = list(recipients)
        if not rs: raise CryptoError('at least one recipient is required')
        for r in rs:
            if not RECIPIENT.match(r): raise CryptoError('recipients must be public age keys (age1...); never pass an identity here')
        self.recipients, self.binary, self.timeout = rs, list(binary), timeout

    def _run(self, args, data):
        try: r = subprocess.run(self.binary + args, input=data, capture_output=True, timeout=self.timeout)
        except subprocess.TimeoutExpired: raise CryptoError(f'age timed out after {self.timeout}s')
        except OSError as e: raise CryptoError(f'cannot run age: {e}')
        if r.returncode != 0: raise CryptoError('age failed: ' + r.stderr.decode('utf-8', 'replace')[:300].strip())
        return r.stdout

    def encrypt(self, plaintext: bytes) -> bytes:
        out = self._run([a for r in self.recipients for a in ('-r', r)], plaintext)
        if not out or out == plaintext: raise CryptoError('age produced no ciphertext')
        return out

    def decrypt(self, ciphertext: bytes, identity_file: str) -> bytes:
        """Used only by restore drills, on a machine that holds the identity. Authentication failure (tampered ciphertext) raises CryptoError."""
        return self._run(['-d', '-i', str(identity_file)], ciphertext)
