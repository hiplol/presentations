#!/usr/bin/env python3
"""
Setup:
    pip install -r requirements.txt

Add a presentation:
    python add.py add slides.pptx --title "Quarterly report" \\
        [--description "..."] [--password "secret"] [--vouchers 2]

Issue one more voucher:
    python add.py voucher --id <PRESENTATION_ID> [--note "for John"]

Master password is prompted interactively. It is used to wrap/unwrap the
KEK inside vouchers and is NOT stored in any file. Remember it — without it
you cannot issue new vouchers.
"""
import argparse, os, sys, json, uuid, secrets, base64, subprocess, shutil, getpass
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent
PRES_DIR = ROOT / "presentations"
DATA = ROOT / "data.json"
ITER = 200000


def derive(pw: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=salt, iterations=ITER).derive(pw)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def load_data() -> dict:
    if not DATA.exists():
        return {"presentations": [], "vouchers": []}
    with open(DATA, encoding="utf-8") as f:
        return json.load(f)


def save_data(d: dict) -> None:
    with open(DATA, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


def convert_pptx_to_pdf(src: str, outdir: str):
    for cmd in ("libreoffice", "soffice"):
        if not shutil.which(cmd):
            continue
        try:
            subprocess.run(
                [cmd, "--headless", "--convert-to", "pdf", "--outdir", outdir, src],
                check=True, capture_output=True, timeout=180,
            )
            pdf = os.path.join(outdir, os.path.splitext(os.path.basename(src))[0] + ".pdf")
            if os.path.exists(pdf):
                return pdf
        except Exception as e:
            print(f"[!] {cmd}: {e}", file=sys.stderr)
    return None


def cmd_add(args):
    if not args.file.lower().endswith(".pptx"):
        sys.exit("Please supply a .pptx file")

    master = os.environ.get("MASTER_PASS") or getpass.getpass("Master password: ")
    if not master:
        sys.exit("Master password is required")

    pid = uuid.uuid4().hex[:10]
    pdir = PRES_DIR / pid
    pdir.mkdir(parents=True, exist_ok=True)

    src_copy = pdir / "source.pptx"
    shutil.copy(args.file, src_copy)

    print("[*] Converting to PDF…")
    pdf_path = convert_pptx_to_pdf(str(src_copy), str(pdir))
    if not pdf_path:
        sys.exit("Conversion failed. Is LibreOffice installed?")
    pdf_bytes = Path(pdf_path).read_bytes()

    if args.password:
        salt, iv = os.urandom(16), os.urandom(12)
        ct = AESGCM(derive(args.password.encode(), salt)).encrypt(iv, pdf_bytes, None)
        (pdir / "slides.pdf.enc").write_bytes(ct)
        os.remove(pdf_path)
        pdf_meta = {
            "file": f"presentations/{pid}/slides.pdf.enc",
            "encrypted": True, "salt": b64(salt), "iv": b64(iv),
        }
    else:
        pdf_meta = {
            "file": f"presentations/{pid}/slides.pdf",
            "encrypted": False,
        }

    # Encrypt source.pptx with the master key
    pres_salt, src_iv = os.urandom(16), os.urandom(12)
    kek = derive(master.encode(), pres_salt)
    src_ct = AESGCM(kek).encrypt(src_iv, src_copy.read_bytes(), None)
    (pdir / "source.pptx.enc").write_bytes(src_ct)
    os.remove(src_copy)

    db = load_data()

    codes = []
    for _ in range(args.vouchers):
        code = secrets.token_hex(16).upper()
        v_salt, v_iv = os.urandom(16), os.urandom(12)
        v_key = derive(code.encode(), v_salt)
        enc_kek = AESGCM(v_key).encrypt(v_iv, kek, None)
        db["vouchers"].append({
            "id": uuid.uuid4().hex[:10],
            "presentation_id": pid,
            "salt": b64(v_salt), "iv": b64(v_iv),
            "encrypted_key": b64(enc_kek),
            "created": datetime.now().isoformat(timespec="seconds"),
            "note": "",
        })
        codes.append(code)

    db["presentations"].append({
        "id": pid,
        "title": args.title,
        "description": args.description or "",
        "created": datetime.now().strftime("%Y-%m-%d"),
        "locked": bool(args.password),
        "pdf": pdf_meta,
        "source": {
            "file": f"presentations/{pid}/source.pptx.enc",
            "salt": b64(pres_salt),
            "iv": b64(src_iv),
        },
    })
    save_data(db)

    print("\n=== DONE ===")
    print(f"ID:        {pid}")
    print(f"Password:  {'set' if args.password else 'none'}")
    print(f"Files:     presentations/{pid}/")
    print("\nVouchers for downloading the PPTX:")
    for c in codes:
        print(f"  {c}")
    print("\nCommit with: git add . && git commit -m 'add presentation' && git push")


def cmd_voucher(args):
    db = load_data()
    pres = next((p for p in db["presentations"] if p["id"] == args.id), None)
    if not pres:
        sys.exit("Presentation not found")

    master = os.environ.get("MASTER_PASS") or getpass.getpass("Master password: ")
    pres_salt = base64.b64decode(pres["source"]["salt"])
    kek = derive(master.encode(), pres_salt)

    code = secrets.token_hex(16).upper()
    v_salt, v_iv = os.urandom(16), os.urandom(12)
    v_key = derive(code.encode(), v_salt)
    enc_kek = AESGCM(v_key).encrypt(v_iv, kek, None)

    db["vouchers"].append({
        "id": uuid.uuid4().hex[:10],
        "presentation_id": args.id,
        "salt": b64(v_salt), "iv": b64(v_iv),
        "encrypted_key": b64(enc_kek),
        "created": datetime.now().isoformat(timespec="seconds"),
        "note": args.note or "",
    })
    save_data(db)

    print(f"Voucher for \"{pres['title']}\":\n  {code}")
    print("Commit data.json")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="Add a presentation")
    a.add_argument("file")
    a.add_argument("--title", required=True)
    a.add_argument("--description", default="")
    a.add_argument("--password", help="View password")
    a.add_argument("--vouchers", type=int, default=1)
    a.set_defaults(func=cmd_add)

    v = sub.add_parser("voucher", help="Issue one more voucher")
    v.add_argument("--id", required=True)
    v.add_argument("--note", default="")
    v.set_defaults(func=cmd_voucher)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
  
