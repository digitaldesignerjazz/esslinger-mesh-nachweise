#!/usr/bin/env python3
"""Prüfskript für Nachweis-Log und Nachweis-Datei (Phase 1, nur lesend).

Rechnet alles nach, ohne dem Sammler zu vertrauen:
 1. Hash-Kette (seq, prev_hash, record_hash) und Merkle-Wurzel des Logs
 2. Nachweis-Datei: SHA-256 des Logs, Wurzel, erster/letzter Hash, Probelauf-Kennzeichnung
 3. Validator-Sets: Hash aus den Schlüsseln neu berechnet
 4. Jeder Block: Header-Hash = Block-ID, Kette über last_block_id, Höhen lückenlos,
    jede Commit-Signatur offline per Ed25519 geprüft
 5. Auswertung (Signaturanteil, Lücken > 60 s, Abdeckung, Uptime) neu gerechnet und verglichen
 6. Phase 2: Prüfer-Signatur jedes Datensatzes und der Nachweis-Datei (checker_pubkey.json),
    ältere Logs/Nachweise nur über die signierte Genesis-Bescheinigung (Datei-SHA-256 + Kopf-Hash),
    Bescheinigungs-Log (Kette + Signaturen), Anschluss an den vorherigen Lauf (--continue)
 7. optional --rpc-check N: N zufällige Höhen je Chain plus erste/letzte erneut per RPC lesen
    und mit dem Log vergleichen (gedrosselt, nur lesend)

Beispiel: python3 verify_epoch.py nachweise/<run_id>.json --rpc nexus-xcoin-1=127.0.0.1:36657 \
              --rpc nexus-qcoin-1=127.0.0.1:37657 --rpc-check 50
Exit-Code 0 = alles OK, 1 = Abweichung gefunden.
"""
import argparse, hashlib, json, os, random, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mp_common import (RPC, canon, check_entry, header_hash, merkle_root, record_hash,
                       summarize_chain, validator_set_hash)
import checker_sig as cs

HERE = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("proof", help="Nachweis-Datei (JSON)")
    ap.add_argument("--log", help="Log-Datei (Standard: aus der Nachweis-Datei)")
    ap.add_argument("--rpc", action="append", default=[], help="chain_id=host:port für --rpc-check")
    ap.add_argument("--rpc-check", type=int, default=0, help="Anzahl zufälliger Höhen je Chain zum Abgleich")
    ap.add_argument("--report", help="Bericht als JSON hierhin schreiben (neue Datei)")
    ap.add_argument("--pubkey", help="öffentlicher Prüferschlüssel (Standard: <Basis>/checker_pubkey.json)")
    ap.add_argument("--attest", help="Bescheinigungs-Log (Standard: <Basis>/attest/attestations.jsonl)")
    a = ap.parse_args()

    fails, notes = [], []
    def fail(msg):
        fails.append(msg)
        print("FEHLER:", msg)

    proof_path = Path(a.proof)
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    log_path = Path(a.log) if a.log else (proof_path.parent.parent / proof["log"]["file"])
    raw = log_path.read_bytes()
    recs = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]

    # 1. Hash-Kette
    prev = "0" * 64
    for i, r in enumerate(recs):
        if r["seq"] != i:
            fail(f"seq {r['seq']} an Position {i}")
        if r["prev_hash"] != prev:
            fail(f"prev_hash falsch bei seq {r['seq']}")
        if record_hash(r) != r["record_hash"]:
            fail(f"record_hash falsch bei seq {r['seq']}")
        prev = r["record_hash"]
    print(f"[1] Hash-Kette: {len(recs)} Datensätze geprüft")
    close = recs[-1]
    if close["type"] != "run_close":
        fail("letzter Datensatz ist nicht run_close")
    n = close["body"]["records_before_close"]
    root = merkle_root([bytes.fromhex(r["record_hash"]) for r in recs[:n]]).hex()
    if root != close["body"]["merkle_root"]:
        fail("Merkle-Wurzel im Log stimmt nicht")
    print(f"[1] Merkle-Wurzel: {root}")

    # 2. Nachweis-Datei
    pl = proof["log"]
    checks2 = [("sha256", hashlib.sha256(raw).hexdigest()), ("records", len(recs)),
               ("first_hash", recs[0]["record_hash"]), ("last_hash", recs[-1]["record_hash"]),
               ("merkle_root", root)]
    for k, v in checks2:
        if pl.get(k) != v:
            fail(f"Nachweis-Datei log.{k} stimmt nicht")
    is_probe = proof.get("counted") is False and "PROBELAUF" in proof.get("status", "") \
        and recs[0]["body"].get("probelauf") is True
    if not is_probe:
        fail("nicht eindeutig als Probelauf (nicht gewertet) gekennzeichnet")
    print(f"[2] Nachweis-Datei passt zum Log; Status: {proof.get('status')}")

    # 6. Prüfer-Signaturen (Phase 2)
    base = proof_path.resolve().parent.parent
    pub = cs.load_pub(a.pubkey or base / "checker_pubkey.json")
    att = cs.verify_attestations(pub, a.attest or base / "attest" / "attestations.jsonl")
    for f_ in att["fails"]:
        fail(f_)
    log_rel = proof["log"]["file"]
    proof_rel = f"nachweise/{proof_path.name}"
    g_log, g_proof = cs.genesis_covers(att, log_rel), cs.genesis_covers(att, proof_rel)
    signed = [r for r in recs if "checker_sig" in r]
    checker_res = {"key_id": pub["key_id"], "fingerprint_sha256": pub["fingerprint_sha256"],
                   "attestations": len(att["records"]), "attestations_ok": att["ok"]}
    if signed or not g_log:
        bad = [r["seq"] for r in recs if r.get("checker_key_id") != pub["key_id"]
               or not cs.verify_hash(record_hash(r), r.get("checker_sig"), pub)]
        if bad:
            fail(f"Prüfer-Signatur fehlt oder ungültig bei {len(bad)} Datensätzen (z. B. seq {bad[:5]})")
        checker_res["log"] = {"mode": "jeder Datensatz signiert", "records_signed_valid": len(recs) - len(bad)}
    else:
        if g_log["file_sha256"] != hashlib.sha256(raw).hexdigest() or g_log["head_hash"] != recs[-1]["record_hash"] \
                or g_log["records"] != len(recs):
            fail("Log passt nicht zur Genesis-Bescheinigung (Datei-Hash/Kopf/Anzahl)")
        checker_res["log"] = {"mode": "Genesis-Bescheinigung", "head_hash": recs[-1]["record_hash"]}
    sigp = proof.get("signature")
    if isinstance(sigp, dict):
        ph = hashlib.sha256(canon({k: v for k, v in proof.items() if k != "signature"})).hexdigest()
        if sigp.get("proof_hash") != ph or not cs.verify_hash(ph, sigp, pub):
            fail("Prüfer-Signatur der Nachweis-Datei ungültig")
        if (proof.get("verifier") or {}).get("pubkey") != pub["pubkey_hex"]:
            fail("verifier.pubkey in der Nachweis-Datei passt nicht zum Prüferschlüssel")
        checker_res["proof"] = "signiert"
    elif g_proof:
        if g_proof["file_sha256"] != hashlib.sha256(proof_path.read_bytes()).hexdigest():
            fail("Nachweis-Datei passt nicht zur Genesis-Bescheinigung")
        checker_res["proof"] = "Genesis-Bescheinigung"
    else:
        fail("Nachweis-Datei weder signiert noch von der Genesis-Bescheinigung erfasst")
    print(f"[6] Prüfer {pub['key_id']}: Log {checker_res['log']['mode']}, Nachweis {checker_res.get('proof')}, "
          f"Bescheinigungen {len(att['records'])} {'OK' if att['ok'] else 'FEHLER'}")

    # Anschluss an den vorherigen Lauf
    prev_run = recs[0]["body"].get("previous_run")
    first_by_chain = {}
    for r in recs:
        if r["type"] == "validator_batch":
            first_by_chain.setdefault(r["body"]["chain_id"], r["body"]["entries"][0])
    if prev_run:
        plog = base / prev_run["log_file"]
        pnw = base / prev_run["nachweis_file"]
        if not plog.exists() or not pnw.exists():
            fail(f"vorheriger Lauf {prev_run['run_id']} fehlt ({plog.name})")
        else:
            with open(plog, "rb") as fh:
                last_line = fh.read().decode("utf-8").splitlines()[-1]
            if json.loads(last_line)["record_hash"] != prev_run["log_last_hash"]:
                fail("previous_run.log_last_hash passt nicht zum vorherigen Log")
            if hashlib.sha256(pnw.read_bytes()).hexdigest() != prev_run["nachweis_sha256"]:
                fail("previous_run.nachweis_sha256 passt nicht")
            for cid, pl_ in prev_run["last"].items():
                e = first_by_chain.get(cid)
                if e is None:
                    fail(f"{cid}: im neuen Lauf keine Blöcke")
                    continue
                if int(e["header"]["height"]) != pl_["height"] + 1 or \
                        (e["header"].get("last_block_id") or {}).get("hash", "").upper() != pl_["block_id_hash"]:
                    fail(f"{cid}: kein lückenloser Anschluss an den vorherigen Lauf")
            print(f"[6] Anschluss an {prev_run['run_id']} geprüft")
        checker_res["previous_run"] = prev_run["run_id"]

    # 3.–5. Je Chain
    by_chain = {}
    for r in recs:
        b = r["body"]
        if r["type"] == "validator_set":
            c = by_chain.setdefault(b["chain_id"], {"valsets": {}, "entries": [], "summary": None})
            calc = validator_set_hash(b["validators"])
            if calc != b["validators_hash"]:
                fail(f"{b['chain_id']}: Validator-Set-Hash {calc} != {b['validators_hash']}")
            c["valsets"][b["validators_hash"]] = b["validators"]
        elif r["type"] == "validator_batch":
            c = by_chain.setdefault(b["chain_id"], {"valsets": {}, "entries": [], "summary": None})
            c["entries"] += b["entries"]
        elif r["type"] == "chain_summary":
            by_chain[b["chain_id"]]["summary"] = b
    proof_sums = {s["chain_id"]: s for s in proof["measurements"]["validator_uptime"]}
    results = {}
    for cid, c in by_chain.items():
        valmaps = {h: {v["address"]: v["pub_key"]["value"] for v in vs} for h, vs in c["valsets"].items()}
        chk = []
        for e in c["entries"]:
            vh = e["header"]["validators_hash"].upper()
            if vh not in valmaps:
                fail(f"{cid}: Validator-Set {vh} fehlt im Log (Höhe {e['header']['height']})")
                continue
            res = check_entry(e, valmaps[vh])
            for err in res["errors"]:
                fail(f"{cid}: {err}")
            chk.append(res)
        s = summarize_chain(cid, c["entries"], chk, c["valsets"])
        if not s["contiguous"]:
            fail(f"{cid}: Höhen nicht lückenlos")
        if s["last_block_id_link_errors"]:
            fail(f"{cid}: {s['last_block_id_link_errors']} Brüche in der last_block_id-Kette")
        logged = dict(c["summary"] or {})
        for k in ("collector_errors", "collector_error_count", "collect_seconds"):
            logged.pop(k, None)
        if canon(logged) != canon(s):
            fail(f"{cid}: Auswertung im Log weicht von der Neuberechnung ab")
        ps = dict(proof_sums.get(cid) or {})
        for k in ("collector_errors", "collector_error_count", "collect_seconds"):
            ps.pop(k, None)
        if canon(ps) != canon(s):
            fail(f"{cid}: Auswertung in der Nachweis-Datei weicht von der Neuberechnung ab")
        sig_ok = sum(1 for r in chk for v in r["sigs"].values() if v["valid"])
        results[cid] = {"blocks": s["blocks_checked"], "heights": s["heights"], "header_hash_ok": s["header_hash_ok"],
                        "signatures_valid": sig_ok, "gaps_over_60s": s["gaps_over_60s"],
                        "validators": s["validators"]}
        v0 = s["validators"][0]
        print(f"[3-5] {cid}: {s['blocks_checked']} Blöcke {s['heights']}, Header-Hash OK {s['header_hash_ok']}, "
              f"gültige Signaturen {sig_ok}, Lücken>60s {s['gaps_over_60s']}, "
              f"Signaturanteil {v0['sig_ratio']*100:.3f} %, Abdeckung {v0['time_coverage']*100:.3f} %, "
              f"Uptime {v0['uptime']*100:.3f} %")

    # 7. Abgleich mit RPC
    if a.rpc_check and a.rpc:
        rng = random.SystemRandom()
        for spec in a.rpc:
            cid, hp = spec.split("=", 1)
            host, port = hp.rsplit(":", 1)
            if cid not in by_chain:
                continue
            ents = {int(e["header"]["height"]): e for e in by_chain[cid]["entries"]}
            hs = sorted(ents)
            sample = sorted({hs[0], hs[-1], *rng.sample(hs, min(a.rpc_check, len(hs)))})
            rpc = RPC(host, int(port), 0.05)
            st = rpc.get("/status")
            if st["node_info"]["network"] != cid:
                fail(f"RPC {spec} gehört zu {st['node_info']['network']}")
                continue
            bad = 0
            for h in sample:
                sh = rpc.get("/commit", height=h)["signed_header"]
                if sh["commit"]["block_id"]["hash"].upper() != ents[h]["commit"]["block_id"]["hash"].upper() \
                        or header_hash(sh["header"]) != header_hash(ents[h]["header"]):
                    bad += 1
                    fail(f"{cid}: Höhe {h} weicht vom laufenden Knoten ab")
            results.setdefault(cid, {})["rpc_check"] = {"heights": len(sample), "mismatch": bad}
            print(f"[7] {cid}: {len(sample)} Höhen gegen RPC {hp} abgeglichen, Abweichungen {bad}")
    else:
        notes.append("kein RPC-Abgleich angefordert")

    # Software-Stand (nur Hinweis)
    cur = {f: hashlib.sha256((HERE / f).read_bytes()).hexdigest()
           for f in recs[0]["body"].get("software_sha256", {}) if (HERE / f).exists()}
    if cur != recs[0]["body"].get("software_sha256"):
        notes.append("Software hat sich seit dem Sammellauf geändert (nur Hinweis)")

    ok = not fails
    print("ERGEBNIS:", "OK – alles nachgerechnet und stimmig" if ok else f"FEHLGESCHLAGEN ({len(fails)} Abweichungen)")
    for nt in notes:
        print("Hinweis:", nt)
    if a.report:
        rep = {"proof": str(proof_path), "log": str(log_path), "ok": ok, "failures": fails[:200],
               "failure_count": len(fails), "notes": notes, "records": len(recs), "merkle_root": root,
               "status": proof.get("status"), "chains": results, "checker": checker_res}
        with open(a.report, "x", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
