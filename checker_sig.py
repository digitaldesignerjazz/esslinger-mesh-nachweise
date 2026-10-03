"""Prüferschlüssel der Box (Phase 2): Ed25519, nur für Nachweise.

Signiert wird immer:  b"esslinger-checker-v1\\x00" || bytes.fromhex(record_hash)
(record_hash = SHA-256 über kanonisches JSON des Datensatzes ohne record_hash und checker_sig).

- Der geheime Schlüssel liegt NUR in keys/checker.key (0600, Ordner 0700, nie in Git, nie ausgegeben).
- Veröffentlicht wird nur checker_pubkey.json (öffentlicher Schlüssel + Fingerabdruck).
- Prüfen braucht nur checker_pubkey.json – kein Geheimnis.
"""
import datetime, hashlib, json, os, stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOMAIN = b"esslinger-checker-v1\x00"
KEY_PATH = HERE / "keys" / "checker.key"
PUB_PATH = HERE / "checker_pubkey.json"
ATTEST_PATH = HERE / "attest" / "attestations.jsonl"
ATTEST_FORMAT = "esslinger-checker/attestation-1"
SIG_FIELDS = ("record_hash", "checker_sig")


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def rec_hash(rec: dict, exclude=SIG_FIELDS) -> str:
    """Datensatz-Hash ohne record_hash/checker_sig. Für Datensätze ohne checker_sig identisch mit Phase 1."""
    return sha256_hex(canon({k: v for k, v in rec.items() if k not in exclude}))


def fingerprint(pub: bytes) -> str:
    return sha256_hex(pub)


def key_id(pub: bytes) -> str:
    return "ck1-" + fingerprint(pub)[:16]


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------- öffentlicher Schlüssel ----------
def load_pub(path=None) -> dict:
    p = Path(path) if path else PUB_PATH
    d = json.loads(p.read_text(encoding="utf-8"))
    pub = bytes.fromhex(d["pubkey_hex"])
    if len(pub) != 32 or d["fingerprint_sha256"] != fingerprint(pub) or d["key_id"] != key_id(pub):
        raise ValueError(f"{p}: öffentlicher Schlüssel und Fingerabdruck passen nicht zusammen")
    d["_pub"] = pub
    return d


def verify_hash(record_hash_hex: str, sigobj, pubinfo: dict) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        if not isinstance(sigobj, dict) or sigobj.get("alg") != "ed25519" or sigobj.get("key_id") != pubinfo["key_id"]:
            return False
        Ed25519PublicKey.from_public_bytes(pubinfo["_pub"]).verify(
            bytes.fromhex(sigobj["sig"]), DOMAIN + bytes.fromhex(record_hash_hex))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def verify_record(rec: dict, pubinfo: dict) -> dict:
    """Prüft record_hash und checker_sig eines Datensatzes."""
    h = rec_hash(rec)
    return {"record_hash_ok": h == rec.get("record_hash"),
            "checker_sig_ok": verify_hash(h, rec.get("checker_sig"), pubinfo)}


# ---------- geheimer Schlüssel (nur auf der Box) ----------
def generate_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    if KEY_PATH.exists() or PUB_PATH.exists():
        raise SystemExit("Prüferschlüssel existiert schon – es wird nichts überschrieben.")
    KEY_PATH.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(KEY_PATH.parent, 0o700)
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    info = {"v": "esslinger-checker/1", "alg": "ed25519", "role": "Prüfer (Box) des Messservers",
            "pubkey_hex": pub.hex(), "fingerprint_sha256": fingerprint(pub), "key_id": key_id(pub),
            "domain": "esslinger-checker-v1\\x00", "signed_message": "domain || bytes.fromhex(record_hash)",
            "created_at": now_utc(),
            "note": "Nur der öffentliche Schlüssel. Der geheime liegt ausschließlich auf der Box (keys/checker.key, 0600) "
                    "und ist von Wallets, Validator- und Mesh-Schlüsseln getrennt."}
    with open(PUB_PATH, "x", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=1)
    return info


class Signer:
    def __init__(self):
        from cryptography.hazmat.primitives import serialization as s
        st = os.stat(KEY_PATH)
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise SystemExit(f"{KEY_PATH} hat zu offene Rechte ({oct(stat.S_IMODE(st.st_mode))}), erwartet 0600.")
        self._sk = s.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
        self.pubinfo = load_pub()
        pub = self._sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        if pub != self.pubinfo["_pub"]:
            raise SystemExit("keys/checker.key passt nicht zu checker_pubkey.json")
        self.key_id = self.pubinfo["key_id"]

    def sign_hash(self, record_hash_hex: str) -> dict:
        return {"alg": "ed25519", "key_id": self.key_id,
                "sig": self._sk.sign(DOMAIN + bytes.fromhex(record_hash_hex)).hex()}

    def seal(self, rec: dict) -> dict:
        """Setzt checker_key_id, record_hash und checker_sig (in dieser Reihenfolge)."""
        rec["checker_key_id"] = self.key_id
        rec["record_hash"] = rec_hash(rec)
        rec["checker_sig"] = self.sign_hash(rec["record_hash"])
        return rec


# ---------- Bescheinigungen (Genesis + Anker), eigenes hash-verkettetes Log ----------
def read_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def append_attestation(signer: Signer, atype: str, body: dict, path=None) -> dict:
    p = Path(path) if path else ATTEST_PATH
    p.parent.mkdir(exist_ok=True)
    prev = read_jsonl(p)
    rec = {"format": ATTEST_FORMAT, "seq": len(prev), "type": atype, "ts": now_utc(),
           "prev_hash": prev[-1]["record_hash"] if prev else "0" * 64, "body": body}
    signer.seal(rec)
    with open(p, "a", encoding="utf-8") as f:
        f.write(canon(rec).decode("utf-8") + "\n")
        f.flush()
        os.fsync(f.fileno())
    return rec


def verify_attestations(pubinfo: dict, path=None) -> dict:
    """Prüft Kette und Signaturen aller Bescheinigungen. Gibt Genesis und alle Köpfe zurück."""
    recs = read_jsonl(Path(path) if path else ATTEST_PATH)
    fails, prev = [], "0" * 64
    for i, r in enumerate(recs):
        if r.get("format") != ATTEST_FORMAT or r.get("seq") != i or r.get("prev_hash") != prev:
            fails.append(f"Bescheinigung {i}: Kette/Format falsch")
        v = verify_record(r, pubinfo)
        if not v["record_hash_ok"]:
            fails.append(f"Bescheinigung {i}: record_hash falsch")
        if not v["checker_sig_ok"]:
            fails.append(f"Bescheinigung {i}: Prüfer-Signatur ungültig")
        prev = r.get("record_hash")
    genesis = recs[0] if recs and recs[0].get("type") == "genesis" else None
    if genesis is None:
        fails.append("keine Genesis-Bescheinigung als erster Eintrag")
    return {"ok": not fails, "fails": fails, "records": recs, "genesis": genesis,
            "head": prev if recs else None}


def genesis_covers(att: dict, relpath: str):
    """Eintrag der Genesis-Bescheinigung für eine Datei (relativer Pfad ab messserver/), sonst None."""
    g = att.get("genesis")
    if not g or not att.get("ok"):
        return None
    return g["body"]["files"].get(relpath)


# ---------- Bestandsaufnahme der Nachweis-Dateien (für Genesis und Anker) ----------
PROVE_LOG = "onyx-prove/log/evidence.jsonl"


def _jsonl_head(p: Path) -> dict:
    raw = p.read_bytes()
    recs = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]
    d = {"kind": "jsonl_log", "records": len(recs), "file_sha256": sha256_hex(raw), "bytes": len(raw),
         "head_seq": recs[-1]["seq"] if recs else None, "head_hash": recs[-1]["record_hash"] if recs else None}
    return d


def evidence_files(base=None) -> list:
    """Relative Pfade aller Nachweis-Dateien, die verankert werden (keine Schlüssel, keine Testdaten)."""
    b = Path(base) if base else HERE
    out = sorted(str(p.relative_to(b)) for p in (b / "log").glob("*.jsonl"))
    out += sorted(str(p.relative_to(b)) for p in (b / "nachweise").glob("*.json"))
    if (b / PROVE_LOG).exists():
        out.append(PROVE_LOG)
        for r in read_jsonl(b / PROVE_LOG):  # nur Rohdateien, auf die das echte Log verweist
            out.append("onyx-prove/" + r["raw_file"])
    return out


def snapshot(base=None) -> dict:
    b = Path(base) if base else HERE
    files = {}
    for rel in evidence_files(b):
        p = b / rel
        files[rel] = _jsonl_head(p) if rel.endswith(".jsonl") else {"kind": "file", "file_sha256": sha256_hex(p.read_bytes()),
                                                                    "bytes": p.stat().st_size}
    return files
