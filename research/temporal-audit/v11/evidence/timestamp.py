"""Verify an existing SHA-256 RFC 3161 response under one independently pinned CA.

The optional OpenSSL 3.x executable runs locally. This command never requests a timestamp.
"""
import argparse
import hashlib
import hmac
import os
import re
import shutil
import ssl
import subprocess
import tempfile
from pathlib import Path

from evidence import digest_hex

PEM_CERT = re.compile(rb"\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*")


def verify_timestamp(data_path, response_path, ca_path, ca_sha256, untrusted=None,
                     query=None, token=False):
    """Verify the data imprint, token signature and chain; optionally match the original request."""
    digest_hex(ca_sha256)
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("OpenSSL 3.x was not found")
    ca_bytes = Path(ca_path).read_bytes()
    if not PEM_CERT.fullmatch(ca_bytes):
        raise ValueError("supply one PEM-encoded pinned CA certificate")
    der = ssl.PEM_cert_to_DER_cert(ca_bytes.decode("ascii").strip())
    if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), ca_sha256):
        raise ValueError("CA certificate DER fingerprint mismatch")
    data_sha256 = hashlib.file_digest if hasattr(hashlib,"file_digest") else None
    with Path(data_path).open("rb") as file:
        if data_sha256:
            imprint = data_sha256(file, "sha256").hexdigest()
        else:
            checksum = hashlib.sha256()
            for chunk in iter(lambda:file.read(1<<16), b""):
                checksum.update(chunk)
            imprint = checksum.hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root, receipt, capath = tmp/"ca.pem", tmp/"response.der", tmp/"empty"
        root.write_bytes(ca_bytes); receipt.write_bytes(Path(response_path).read_bytes()); capath.mkdir()
        env = os.environ.copy()
        env.update({"SSL_CERT_FILE":str(root), "SSL_CERT_DIR":str(capath), "OPENSSL_CONF":os.devnull,"LC_ALL":"C"})

        def run(args):
            result = subprocess.run([executable]+args, capture_output=True, text=True,
                                    errors="replace",env=env,timeout=40)
            if result.returncode:
                raise ValueError("OpenSSL verification failed: "+(result.stderr or result.stdout).strip())
            return result.stdout

        if not run(["version"]).startswith("OpenSSL 3."):
            raise ValueError("this verification profile requires OpenSSL 3.x")
        fmt = ["-token_in"] if token else []
        info = run(["ts","-reply","-in",str(receipt),*fmt,"-text"])
        if not re.search(r"^Hash Algorithm:\s*sha256\s*$",info,re.M):
            raise ValueError("expected a SHA-256 timestamp imprint")
        verify = ["ts","-verify","-in",str(receipt),*fmt,"-CAfile",str(root),
                  "-CApath",str(capath),"-CAstore",capath.as_uri()]
        if untrusted is not None:
            chain = tmp/"extra.pem"; chain.write_bytes(Path(untrusted).read_bytes())
            verify += ["-untrusted",str(chain)]
        run(verify+["-digest",imprint])
        if query is not None:
            req = tmp/"request.tsq"; req.write_bytes(Path(query).read_bytes())
            run(verify+["-queryfile",str(req)])
        return info


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("data",type=Path);ap.add_argument("response",type=Path)
    ap.add_argument("--ca",type=Path,required=True);ap.add_argument("--ca-sha256",required=True)
    ap.add_argument("--untrusted",type=Path);ap.add_argument("--query",type=Path)
    ap.add_argument("--token",action="store_true",help="response is a bare CMS timestamp token")
    args=ap.parse_args()
    try:
        result=verify_timestamp(args.data,args.response,args.ca,args.ca_sha256,args.untrusted,args.query,args.token)
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        ap.exit(1,f"Verification failed: {exc}\n")
    print("Verified SHA-256 imprint and timestamp signature under the supplied CA pin.")
    print(result)


if __name__=="__main__":
    main()
