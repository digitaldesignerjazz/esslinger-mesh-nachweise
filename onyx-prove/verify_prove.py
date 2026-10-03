#!/usr/bin/env python3
"""Nachprüfung von log/evidence.jsonl (esslinger-minerproof/1), für jeden wiederholbar.
Prüft: Hash-Kette, Rohdatei-Hashes, Antwort-Signaturen (aus der PeerId), Challenge-Bindung,
mit --rpc die Block-Hashes der Frischemarken gegen die Chain, und (Phase 2) die Prüfer-Signaturen:
 - Datensätze bis zum Kopf der Genesis-Bescheinigung: Kopf-Hash muss exakt passen (keine Signatur nötig)
 - jeder spätere Datensatz: gültige checker_sig (Ed25519 über "esslinger-checker-v1\\0" || record_hash)
 - das Bescheinigungs-Log selbst (Kette + Signaturen)
Braucht nur den öffentlichen Prüferschlüssel (checker_pubkey.json), kein Geheimnis."""
import argparse, json, os, sys, urllib.request
from prove_common import canon, record_hash, sha256_hex, verify_answer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import checker_sig as cs  # noqa: E402


def block_hash(rpc, h):
    with urllib.request.urlopen(f"{rpc}/block?height={h}", timeout=5) as r:
        return json.load(r)["result"]["block_id"]["hash"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=os.path.join(HERE, "log/evidence.jsonl"))
    ap.add_argument("--base", default=HERE, help="Ordner, relativ zu dem raw_file aufgelöst wird")
    ap.add_argument("--pubkey", default=os.path.join(ROOT, "checker_pubkey.json"))
    ap.add_argument("--attest", default=os.path.join(ROOT, "attest/attestations.jsonl"))
    ap.add_argument("--log-name", default=cs.PROVE_LOG, help="Name des Logs in der Genesis-Bescheinigung")
    ap.add_argument("--no-checker", action="store_true", help="nur für alte Test-Logs: Prüfer-Signaturen nicht verlangen")
    ap.add_argument("--rpc")
    a = ap.parse_args()
    prev, ok_all, rows, problems = "0" * 64, True, [], []
    att, gentry, pub = None, None, None
    if not a.no_checker:
        pub = cs.load_pub(a.pubkey)
        att = cs.verify_attestations(pub, a.attest)
        if not att["ok"]:
            ok_all = False
            problems += att["fails"]
        gentry = cs.genesis_covers(att, a.log_name)
    g_seq = gentry["head_seq"] if gentry else -1
    g_head_seen = gentry is None
    for i, line in enumerate(open(a.log)):
        rec = json.loads(line)
        row = {"seq": rec["seq"], "label": rec["target_label"], "status": rec["status"], "result": rec["result"],
               "tampered_for_test": rec.get("tampered_for_test")}
        row["chain_ok"] = rec["prev_hash"] == prev and rec["seq"] == i and record_hash(rec) == rec["record_hash"]
        rawp = os.path.join(a.base, rec["raw_file"])
        row["raw_ok"] = os.path.exists(rawp) and sha256_hex(open(rawp, "rb").read()) == rec["raw_file_sha256"]
        row["challenge_hash_ok"] = sha256_hex(canon(rec["challenge"])) == rec["challenge_hash"]
        if rec.get("answer"):
            v = verify_answer(rec["answer"], rec["expected_peer_id"], rec["challenge"], rec["checker_ephemeral_peer_id"])
            row["answer_ok_now"] = v["ok"]
            row["verdict_consistent"] = (v["ok"] == rec["verification_box"].get("ok"))
        else:
            row["answer_ok_now"] = None
            row["verdict_consistent"] = rec["result"] != "pass"
        if not a.no_checker:
            if rec["seq"] <= g_seq:
                row["checker"] = "genesis"
                if rec["seq"] == g_seq:
                    row["genesis_head_ok"] = rec["record_hash"] == gentry["head_hash"]
                    g_head_seen = True
                if "checker_sig" in rec:
                    row["checker_sig_ok"] = cs.verify_hash(rec["record_hash"], rec["checker_sig"], pub)
            else:
                row["checker"] = "signiert"
                row["checker_sig_ok"] = (rec.get("checker_key_id") == pub["key_id"]
                                         and cs.verify_hash(record_hash(rec), rec.get("checker_sig"), pub))
        if a.rpc:
            for k in ("freshness_before", "freshness_after"):
                m = rec[k]
                row[k + "_ok"] = block_hash(a.rpc, m["height"]).upper() == m["block_hash"].upper()
            row["beacon_in_challenge_ok"] = rec["challenge"]["block_hash"] == rec["freshness_before"]["block_hash"]
        good = all(v is not False for k, v in row.items() if k.endswith("_ok") or k == "verdict_consistent")
        row["record_ok"] = good
        ok_all &= good
        prev = rec["record_hash"]
        rows.append(row)
    if not g_head_seen:
        ok_all = False
        problems.append(f"Genesis-Kopf seq {g_seq} fehlt im Log (gekürzt?)")
    out = {"ok": ok_all, "head": prev, "records": rows, "problems": problems}
    if att is not None:
        out["checker"] = {"key_id": pub["key_id"], "fingerprint_sha256": pub["fingerprint_sha256"],
                          "attestations_ok": att["ok"], "attestations": len(att["records"]),
                          "genesis_covers_up_to_seq": g_seq}
    print(json.dumps(out, indent=1, ensure_ascii=False))
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
