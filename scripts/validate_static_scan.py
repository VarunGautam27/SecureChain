"""Validates the static-scan taint tracer two ways:

1. Against a RECONSTRUCTED sample modeled on the publicly-documented
   technique used in real historical malicious PyPI typosquat incidents
   (e.g. the 2019 fake "python3-dateutil" package: a base64-encoded payload
   in setup.py, decoded and exec'd, exfiltrating SSH/GPG keys over the
   network). This is NOT the original malicious file - PyPI deletes
   confirmed malware outright (unlike npm), so the real source is no longer
   fetchable; this is reconstructed from the publicly reported technique to
   test whether the tracer recognizes the pattern.

2. Against several REAL, currently-published, legitimate PyPI packages that
   perform similar-sounding but benign operations (network calls, encoding,
   subprocess use) - to demonstrate the tracer does not false-positive on
   genuine, widely-used software.
"""

from __future__ import annotations

from securechain.static_scan import StaticScanClient, find_taint_chains

# Reconstructed from the publicly documented technique, not the original file.
RECONSTRUCTED_INCIDENT_SAMPLE = '''
import base64
import os

# In the real 2019 incident, this payload (here shortened/illustrative)
# decoded to code that located SSH/GPG keys and POSTed them to a remote host.
_payload = base64.b64decode(
    "aW1wb3J0IG9zCnByaW50KCdyZWNvbnN0cnVjdGVkIGRlbW8gcGF5bG9hZCcp"
)
exec(_payload)
'''

REAL_PACKAGES_EXPECTED_CLEAN = [
    "requests",
    "paramiko",
    "cryptography",
    "celery",
    "pyyaml",
]


def main() -> None:
    print("=== Reconstructed incident-style sample (expect: FLAGGED) ===")
    findings = find_taint_chains(RECONSTRUCTED_INCIDENT_SAMPLE)
    print("Chain findings:", findings)
    print("Result:", "FLAGGED" if findings else "not flagged")

    print("\n=== Real, currently-published legitimate packages (expect: not flagged) ===")
    client = StaticScanClient()
    for package in REAL_PACKAGES_EXPECTED_CLEAN:
        import requests as _requests

        try:
            resp = _requests.get(f"https://pypi.org/pypi/{package}/json", timeout=10)
            resp.raise_for_status()
            latest = resp.json()["info"]["version"]
        except Exception as exc:  # noqa: BLE001 - best-effort demo script
            print(package, "-> could not resolve latest version:", exc)
            continue

        result = client.scan(package, latest, "pypi")
        print(f"{package}@{latest} -> flagged={result.flagged}, indicators={result.indicators}")


if __name__ == "__main__":
    main()
