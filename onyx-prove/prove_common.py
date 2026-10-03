"""esslinger-minerproof/1 — gemeinsame Funktionen (Standardbibliothek + cryptography).
Signiert wird: b"esslinger-minerproof-v1\\x00" || sha256(canon(body))."""
import hashlib, json

VERSION = "esslinger-minerproof/1"
DOMAIN = b"esslinger-minerproof-v1\x00"
LOG_FORMAT = "esslinger-minerproof/evidence-1"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def record_hash(rec: dict) -> str:
    """ohne record_hash und checker_sig (Phase 2); für ältere Datensätze ohne checker_sig unverändert"""
    return sha256_hex(canon({k: v for k, v in rec.items() if k not in ("record_hash", "checker_sig")}))


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def ed25519_pub_from_peer_id(pid: str) -> bytes:
    b = b58decode(pid)
    assert b[0] == 0x00, "kein identity-Multihash"
    pb = b[2:2 + b[1]]
    assert pb[:4] == bytes([0x08, 0x01, 0x12, 0x20]), "kein Ed25519-Schlüssel"
    return pb[4:36]


def signed_bytes(body: dict) -> bytes:
    return DOMAIN + hashlib.sha256(canon(body)).digest()


def verify_answer(answer: dict, expect_peer_id=None, expect_challenge=None, expect_requester=None) -> dict:
    """Unabhängige Prüfung (nicht der Rust-Code des Knotens)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    r = {}
    try:
        body = answer["body"]
        r["v_ok"] = body.get("v") == VERSION
        pub = ed25519_pub_from_peer_id(body["peer_id"])
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(answer["sig"]), signed_bytes(body))
            r["signature_valid"] = True
        except InvalidSignature:
            r["signature_valid"] = False
        r["challenge_hash_valid"] = body.get("challenge_hash") == sha256_hex(canon(body["challenge"]))
        checks = [r["v_ok"], r["signature_valid"], r["challenge_hash_valid"]]
        if expect_peer_id is not None:
            r["peer_id_matches_expected"] = body["peer_id"] == expect_peer_id
            checks.append(r["peer_id_matches_expected"])
        if expect_challenge is not None:
            r["challenge_matches_sent"] = canon(body["challenge"]) == canon(expect_challenge)
            checks.append(r["challenge_matches_sent"])
        if expect_requester is not None:
            r["requester_matches_checker"] = body.get("requester_peer_id") == expect_requester
            checks.append(r["requester_matches_checker"])
        r["ok"] = all(checks)
    except Exception as e:  # noqa
        r["ok"] = False
        r["error"] = repr(e)
    return r
