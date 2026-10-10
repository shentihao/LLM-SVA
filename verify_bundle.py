"""Verify all distributed files against SHA256SUMS.json, without network access."""
from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parent
manifest=json.loads((root/'SHA256SUMS.json').read_text())
for name,digest in manifest.items():
 p=root/name
 assert p.is_file(),f'Missing: {name}'
 assert hashlib.sha256(p.read_bytes()).hexdigest()==digest,f'Modified: {name}'
print(f'OK: {len(manifest)} distributed files match SHA-256 manifest.')
