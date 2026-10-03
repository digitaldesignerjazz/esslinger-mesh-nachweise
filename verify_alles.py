#!/usr/bin/env python3
"""Prüft ALLE Nachweise in diesem Ordner auf einmal (für jeden wiederholbar, nur lesend, kein Geheimnis):
 1. Bescheinigungs-Log attest/attestations.jsonl: Kette und Prüfer-Signaturen (checker_pubkey.json)
 2. Jede Bescheinigung (Genesis und Anker) gegen die heutigen Dateien: nur anhängbare Logs müssen
    die bescheinigten Datensätze unverändert als Anfang enthalten, alle anderen Dateien unverändert sein
 3. onyx-prove/verify_prove.py (Prüfaufgaben-Log)
 4. verify_epoch.py für jede Nachweis-Datei unter nachweise/
Exit-Code 0 = alles OK, 1 = Abweichung.
Beispiel: python3 verify_alles.py [--rpc-check 20]   (RPC-Abgleich nur auf der Box sinnvoll)
"""
import argparse, hashlib, json, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import checker_sig as cs  # noqa: E402


def prefix_sha(path: Path, n_lines: int):
    lines = path.read_bytes().split(b"\n")
    if len([l for l in lines if l.strip()]) < n_lines:
        return None
    return hashlib.sha256(b"".join(l + b"\n" for l in lines[:n_lines])).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc-check", type=int, default=0)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    fails, out = [], {}
    pub = cs.load_pub(HERE / "checker_pubkey.json")
    att = cs.verify_attestations(pub, HERE / "attest" / "attestations.jsonl")
    fails += att["fails"]
    out["checker"] = {"key_id": pub["key_id"], "fingerprint_sha256": pub["fingerprint_sha256"]}
    out["attestations"] = {"count": len(att["records"]), "ok": att["ok"], "head": att["head"]}
    # 2. Bescheinigungen gegen heutige Dateien
    checked = 0
    for r in att["records"]:
        for rel, d in r["body"]["files"].items():
            p = HERE / rel
            if not p.exists():
                fails.append(f"Bescheinigung {r['seq']}: {rel} fehlt")
                continue
            if d["kind"] == "jsonl_log":
                if prefix_sha(p, d["records"]) != d["file_sha256"]:
                    fails.append(f"Bescheinigung {r['seq']}: {rel} enthält die bescheinigten {d['records']} Datensätze nicht unverändert")
            elif hashlib.sha256(p.read_bytes()).hexdigest() != d["file_sha256"]:
                fails.append(f"Bescheinigung {r['seq']}: {rel} wurde verändert")
            checked += 1
    out["attested_files_checked"] = checked
    # 3. Prüfaufgaben-Log
    if (HERE / cs.PROVE_LOG).exists():
        p = subprocess.run([sys.executable, str(HERE / "onyx-prove" / "verify_prove.py")], capture_output=True, text=True)
        try:
            d = json.loads(p.stdout)
            out["prove_log"] = {"ok": d["ok"], "records": len(d["records"]), "head": d["head"],
                                "pass": sum(1 for x in d["records"] if x["result"] == "pass"),
                                "signed": sum(1 for x in d["records"] if x.get("checker") == "signiert")}
        except Exception:
            out["prove_log"] = {"ok": False, "stderr": p.stderr[-500:]}
        if p.returncode != 0:
            fails.append("verify_prove.py: FEHLGESCHLAGEN")
    # 4. Nachweis-Dateien
    out["epochs"] = {}
    for nw in sorted((HERE / "nachweise").glob("*.json")):
        if nw.name.endswith(".verify.json"):
            continue
        cmd = [sys.executable, str(HERE / "verify_epoch.py"), str(nw)]
        if a.rpc_check:
            cmd += ["--rpc", "nexus-xcoin-1=127.0.0.1:36657", "--rpc", "nexus-qcoin-1=127.0.0.1:37657",
                    "--rpc-check", str(a.rpc_check)]
        p = subprocess.run(cmd, capture_output=True, text=True)
        ok = p.returncode == 0
        out["epochs"][nw.stem] = "OK" if ok else "FEHLER"
        if not ok:
            fails.append(f"verify_epoch.py {nw.name}: " + " | ".join(l for l in p.stdout.splitlines() if "FEHLER" in l)[:400])
    # 5. Epochen (Vorab-Bescheinigung, Ereignis-Log, Offenlegung)
    if list((HERE / "epochs").glob("epoch-*/epoch-*.json")):
        p = subprocess.run([sys.executable, str(HERE / "epoche.py"), "verify", "--base", str(HERE)],
                           capture_output=True, text=True)
        try:
            d = json.loads(p.stdout)
            out["epochs_m1"] = {k: {kk: v.get(kk) for kk in ("ok", "events", "probe_slots_recorded", "outcomes",
                                                               "revealed", "fails")} for k, v in d["epochs"].items()}
        except Exception:
            out["epochs_m1"] = {"ok": False, "stderr": p.stderr[-500:]}
        if p.returncode != 0:
            fails.append("epoche.py verify: FEHLGESCHLAGEN " + json.dumps(out["epochs_m1"], ensure_ascii=False)[:400])
    out["ok"] = not fails
    out["failures"] = fails
    print(json.dumps(out, indent=1, ensure_ascii=False))
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
