"""Gemeinsame Funktionen für den Messserver (Miner-Nachweis), Phase 1.

Nur lesend: RPC-Abfragen an CometBFT, Offline-Prüfung von Commit-Signaturen,
Header- und Validator-Set-Hashes, Hash-Kette und Merkle-Wurzel (RFC 6962).
Keine Schlüssel, keine Transaktionen, keine Hintergrundprozesse.
"""
import base64, calendar, hashlib, http.client, json, struct, time, urllib.parse

FORMAT = "esslinger-minerproof/1"
GAP_THRESHOLD_S = 60  # Blockabstand > 60 s zählt als Ausfall


# ---------- kanonisches JSON und Hashes ----------
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def record_hash(rec: dict) -> str:
    """Hash eines Log-Datensatzes ohne die Felder record_hash und checker_sig (Phase 2).
    Für Datensätze ohne checker_sig (Phase 1) ist das Ergebnis unverändert."""
    r = {k: v for k, v in rec.items() if k not in ("record_hash", "checker_sig")}
    return sha256(canon(r)).hex()


# ---------- Merkle (RFC 6962 / CometBFT simple merkle) ----------
def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(items) -> bytes:
    n = len(items)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return sha256(b"\x00" + items[0])
    k = _split(n)
    return sha256(b"\x01" + merkle_root(items[:k]) + merkle_root(items[k:]))


# ---------- Protobuf-Minimalkodierung ----------
def _v(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def _key(no, wt):
    return _v(no << 3 | wt)


def _ld(no, b):
    return _key(no, 2) + _v(len(b)) + b


def _uvarint_field(no, n):
    return _key(no, 0) + _v(n) if n else b""


def _int64_varint_field(no, n):
    if not n:
        return b""
    if n < 0:
        n += 1 << 64
    return _key(no, 0) + _v(n)


def parse_time(s: str):
    """RFC3339 mit Nanosekunden -> (sekunden, nanos), ohne Float-Rundung."""
    s = s.rstrip("Z")
    main, frac = (s.split(".") + ["0"])[:2]
    sec = calendar.timegm(time.strptime(main, "%Y-%m-%dT%H:%M:%S"))
    nanos = int(frac.ljust(9, "0")[:9])
    return sec, nanos


def time_ns(s: str) -> int:
    sec, nanos = parse_time(s)
    return sec * 1_000_000_000 + nanos


def _timestamp(s: str) -> bytes:
    sec, nanos = parse_time(s)
    return _int64_varint_field(1, sec) + _uvarint_field(2, nanos)


def _hexb(h):
    return bytes.fromhex(h) if h else b""


def _block_id(bid: dict) -> bytes:
    """BlockID-Proto (PartSetHeader nicht nullable, wird immer kodiert)."""
    parts = bid.get("parts") or {}
    psh = _uvarint_field(1, int(parts.get("total") or 0)) + (_ld(2, _hexb(parts.get("hash"))) if parts.get("hash") else b"")
    h = _hexb(bid.get("hash"))
    return (_ld(1, h) if h else b"") + _ld(2, psh)


def _cdc_bytes(h):  # gogotypes.BytesValue, leer -> nil
    b = _hexb(h)
    return _ld(1, b) if b else b""


def header_hash(hd: dict) -> str:
    """CometBFT Header.Hash() nachgebaut (v0.38)."""
    ver = hd.get("version") or {}
    hbz = _uvarint_field(1, int(ver.get("block") or 0)) + _uvarint_field(2, int(ver.get("app") or 0))
    chain = hd["chain_id"].encode()
    leaves = [
        hbz,
        _ld(1, chain) if chain else b"",
        _int64_varint_field(1, int(hd["height"])),
        _timestamp(hd["time"]),
        _block_id(hd.get("last_block_id") or {}),
        _cdc_bytes(hd.get("last_commit_hash")),
        _cdc_bytes(hd.get("data_hash")),
        _cdc_bytes(hd.get("validators_hash")),
        _cdc_bytes(hd.get("next_validators_hash")),
        _cdc_bytes(hd.get("consensus_hash")),
        _cdc_bytes(hd.get("app_hash")),
        _cdc_bytes(hd.get("last_results_hash")),
        _cdc_bytes(hd.get("evidence_hash")),
        _cdc_bytes(hd.get("proposer_address")),
    ]
    return merkle_root(leaves).hex().upper()


def validator_set_hash(vals: list) -> str:
    """ValidatorSet.Hash(): Merkle über SimpleValidator{PublicKey{ed25519}, voting_power}."""
    items = []
    for v in vals:
        if v["pub_key"]["type"] != "tendermint/PubKeyEd25519":
            raise ValueError("nur Ed25519 unterstützt: " + v["pub_key"]["type"])
        pk = _ld(1, base64.b64decode(v["pub_key"]["value"]))
        items.append(_ld(1, pk) + _int64_varint_field(2, int(v["voting_power"])))
    return merkle_root(items).hex().upper()


def vote_sign_bytes(chain_id: str, height: int, rnd: int, block_id: dict, ts: str) -> bytes:
    """CanonicalVote (Precommit), längenpräfixiert, wie CometBFT VoteSignBytes."""
    parts = block_id["parts"]
    psh = _uvarint_field(1, int(parts["total"])) + _ld(2, bytes.fromhex(parts["hash"]))
    cbid = _ld(1, bytes.fromhex(block_id["hash"])) + _ld(2, psh)
    msg = (_key(1, 0) + _v(2)
           + _key(2, 1) + struct.pack("<q", height)
           + ((_key(3, 1) + struct.pack("<q", rnd)) if rnd else b"")
           + _ld(4, cbid)
           + _ld(5, _timestamp(ts))
           + _ld(6, chain_id.encode()))
    return _v(len(msg)) + msg


def verify_ed25519(pub_b64: str, sig_b64: str, msg: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------- Prüfung eines Block-Eintrags ----------
def check_entry(entry: dict, valset: dict) -> dict:
    """Prüft einen Eintrag {header, commit} gegen ein Validator-Set {address: pubkey}.
    Gibt pro Validator zurück, ob eine gültige Signatur vorliegt."""
    hd, cm = entry["header"], entry["commit"]
    res = {"height": int(hd["height"]), "header_hash_ok": False, "sigs": {}, "errors": []}
    hh = header_hash(hd)
    if hh != cm["block_id"]["hash"].upper():
        res["errors"].append(f"header_hash {hh} != block_id {cm['block_id']['hash']}")
    else:
        res["header_hash_ok"] = True
    if int(cm["height"]) != int(hd["height"]):
        res["errors"].append("commit.height != header.height")
    for s in cm["signatures"]:
        addr = s.get("validator_address") or ""
        flag = int(s["block_id_flag"])
        if flag != 2:  # 1 = absent, 3 = nil
            res["sigs"][addr or f"absent#{len(res['sigs'])}"] = {"flag": flag, "valid": False}
            continue
        pub = valset.get(addr)
        if pub is None:
            res["errors"].append(f"unbekannter Validator {addr}")
            res["sigs"][addr] = {"flag": flag, "valid": False}
            continue
        sb = vote_sign_bytes(hd["chain_id"], int(hd["height"]), int(cm["round"]), cm["block_id"], s["timestamp"])
        ok = verify_ed25519(pub, s["signature"], sb)
        if not ok:
            res["errors"].append(f"Signatur ungültig {addr} @ {hd['height']}")
        res["sigs"][addr] = {"flag": flag, "valid": ok}
    return res


# ---------- Auswertung ----------
def summarize_chain(chain_id: str, entries: list, checks: list, valsets: dict) -> dict:
    """entries: geordnete Einträge, checks: Ergebnisse von check_entry, valsets: hash -> [validators].
    Rechnet sig_ratio, Lücken > 60 s, time_coverage, Uptime je Validator."""
    n = len(entries)
    heights = [int(e["header"]["height"]) for e in entries]
    contiguous = heights == list(range(heights[0], heights[0] + n)) if n else False
    link_errors = 0
    for i in range(1, n):
        prev_bid = entries[i - 1]["commit"]["block_id"]["hash"].upper()
        if (entries[i]["header"].get("last_block_id") or {}).get("hash", "").upper() != prev_bid:
            link_errors += 1
    times = [time_ns(e["header"]["time"]) for e in entries]
    gaps = []
    for i in range(1, n):
        d = (times[i] - times[i - 1]) / 1e9
        if d > GAP_THRESHOLD_S:
            gaps.append({"after_height": heights[i - 1], "seconds": round(d, 3),
                         "from": entries[i - 1]["header"]["time"], "to": entries[i]["header"]["time"]})
    span_s = (times[-1] - times[0]) / 1e9 if n > 1 else 0.0
    gap_s = sum(g["seconds"] for g in gaps)
    coverage = (1 - gap_s / span_s) if span_s > 0 else 0.0
    intervals = sorted((times[i] - times[i - 1]) / 1e9 for i in range(1, n))
    validators = sorted({a for vs in valsets.values() for a in (v["address"] for v in vs)})
    per_val = []
    for addr in validators:
        valid = sum(1 for c in checks if c["sigs"].get(addr, {}).get("valid"))
        sig_ratio = valid / n if n else 0.0
        per_val.append({"validator": addr, "heights": n, "signed_valid": valid,
                        "sig_ratio": round(sig_ratio, 6), "time_coverage": round(coverage, 6),
                        "uptime": round(min(sig_ratio, coverage), 6)})
    return {
        "chain_id": chain_id,
        "heights": [heights[0], heights[-1]] if n else None,
        "blocks_checked": n,
        "contiguous": contiguous,
        "last_block_id_link_errors": link_errors,
        "header_hash_ok": sum(1 for c in checks if c["header_hash_ok"]),
        "signature_errors": sum(len(c["errors"]) for c in checks),
        "first_block_time": entries[0]["header"]["time"] if n else None,
        "last_block_time": entries[-1]["header"]["time"] if n else None,
        "span_s": round(span_s, 3),
        "block_interval_s": {"median": round(intervals[len(intervals) // 2], 3) if intervals else None,
                             "max": round(intervals[-1], 3) if intervals else None},
        "gaps_over_60s": len(gaps),
        "gap_seconds_total": round(gap_s, 3),
        "gaps": gaps,
        "validator_set_hashes": sorted(valsets.keys()),
        "validators": per_val,
    }


# ---------- RPC (lesend, gedrosselt) ----------
class RPC:
    def __init__(self, host: str, port: int, min_interval_s: float = 0.02):
        self.host, self.port, self.min_interval = host, port, min_interval_s
        self.conn = None
        self.last = 0.0
        self.requests = 0

    def get(self, path: str, **params):
        wait = self.min_interval - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        q = path + ("?" + urllib.parse.urlencode(params) if params else "")
        for attempt in range(3):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection(self.host, self.port, timeout=15)
                self.conn.request("GET", q)
                r = self.conn.getresponse()
                body = r.read()
                self.last = time.monotonic()
                self.requests += 1
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status} für {q}: {body[:200]!r}")
                d = json.loads(body)
                if "error" in d:
                    raise RuntimeError(f"RPC-Fehler für {q}: {d['error']}")
                return d["result"]
            except (ConnectionError, http.client.HTTPException, OSError):
                self.conn = None
                if attempt == 2:
                    raise
                time.sleep(1.0 * (attempt + 1))
