#!/usr/bin/env python3
"""
Outil d'émission des licences NetWatch (côté éditeur).

  keygen  --out DIR                 génère une paire Ed25519 : DIR/private.pem (0600) + DIR/public.txt
  issue   --key DIR/private.pem --kid 2026-09 --customer "PME Exemple" --expires 2027-09-28
          [--sensors 1] [--features ia,reports,compliance,itsm,rbac,support] [--id ...] [--notes ...]
  inspect LICENCE                   décode la charge utile (sans vérifier la signature)

La clé privée ne quitte jamais le poste de l'éditeur (private/license-signing/ n'est
pas dans le dépôt). Seule la clé publique (public.txt) est copiée dans
portal/netwatch/license.py (PUBLIC_KEYS[kid]).
"""
import argparse
import base64
import json
import os
import secrets
import sys
from datetime import date

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64e(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def cmd_keygen(args):
    os.makedirs(args.out, exist_ok=True)
    priv_path = os.path.join(args.out, "private.pem")
    if os.path.exists(priv_path) and not args.force:
        sys.exit(f"{priv_path} existe déjà (--force pour écraser)")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub).decode("ascii")
    with open(os.path.join(args.out, "public.txt"), "w", encoding="utf-8") as f:
        f.write(pub_b64 + "\n")
    print(f"clé privée : {priv_path} (ne jamais la diffuser)")
    print(f"clé publique : {pub_b64}")
    print("→ à copier dans portal/netwatch/license.py : PUBLIC_KEYS[\"<kid>\"]")


def cmd_issue(args):
    with open(args.key, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    features = [x.strip() for x in args.features.split(",") if x.strip()] if args.features else []
    payload = {
        "id": args.id or f"NW-{date.today():%Y%m%d}-{secrets.token_hex(3).upper()}",
        "customer": args.customer,
        "edition": "pro",
        "sensors": args.sensors,
        "issued": date.today().isoformat(),
        "expires": args.expires,
        "features": features,
        "notes": args.notes or "",
    }
    date.fromisoformat(args.expires)  # valide le format
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = key.sign(payload_bytes)
    print(f"NW1.{args.kid}.{b64e(payload_bytes)}.{b64e(sig)}")


def cmd_inspect(args):
    parts = args.license.strip().split(".")
    if len(parts) != 4:
        sys.exit("format inconnu")
    payload = json.loads(base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4)))
    print(f"kid : {parts[1]}")
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main():
    p = argparse.ArgumentParser(description="Licences NetWatch (éditeur)")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out", required=True); k.add_argument("--force", action="store_true")
    i = sub.add_parser("issue")
    i.add_argument("--key", required=True); i.add_argument("--kid", required=True)
    i.add_argument("--customer", required=True); i.add_argument("--expires", required=True, help="AAAA-MM-JJ")
    i.add_argument("--sensors", type=int, default=1); i.add_argument("--features", default="")
    i.add_argument("--id"); i.add_argument("--notes")
    s = sub.add_parser("inspect"); s.add_argument("license")
    args = p.parse_args()
    {"keygen": cmd_keygen, "issue": cmd_issue, "inspect": cmd_inspect}[args.cmd](args)


if __name__ == "__main__":
    main()
