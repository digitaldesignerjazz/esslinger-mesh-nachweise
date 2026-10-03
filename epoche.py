#!/usr/bin/env python3
"""Epochen des Messservers (Phase 4, M1): Festlegung, Plan-Commitment, Ereignis-Log, Nachprüfung.

Unterbefehle:
  init     legt EINMALIG eine Epoche an (epochs/epoch-<n>/epoch-<n>.json + subjects.json), erzeugt den geheimen
           Plan-Seed (keys/epoch-<n>.seed, 0600, nie in Git) und hängt eine vom Prüfer signierte
           Vorab-Bescheinigung (type "epoch_precommit") mit seed_commitment und schedule_commitment an.
  verify   prüft Epochen-Datei, Vorab-Bescheinigung, Ereignis-Log (Kette + Prüfer-Signaturen), Bezug der
           Proben auf das Prüfaufgaben-Log und – nach der Offenlegung – Seed und Plan. Kein Geheimnis nötig.
  summary  Zählt die Ausgänge (Hilfe für die Auswertung von Hand; wertet NICHT selbst).
  reveal   (nur von Hand nach einem vorzeitigen Stopp) legt Seed und Plan offen.

Plan-Algorithmus (esslinger-epoch-schedule/1), aus dem offengelegten Seed für jeden nachrechenbar:
  für Tag d = 0..days-1 (Tageslänge day_s = 86400 s), i = 0,1,2,…:
     h   = HMAC-SHA256(seed, "esslinger-epoch-schedule/1|epoch=<id>|day=<d>|i=<i>")
     off = lo + (uint64_be(h[0:8]) mod (hi - lo))           # Sekunden ab Tagesbeginn der Epoche
     angenommen, wenn |off - o| >= min_gap für alle bisher angenommenen o desselben Tages
  bis per_day Zeitpunkte angenommen sind; t = start_unix + d*day_s + off.
  schedule_commitment = SHA-256(kanonisches JSON des Plans), seed_commitment = SHA-256(seed).
"""
import argparse, datetime as dt, hashlib, hmac, json, os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import checker_sig as cs  # noqa: E402

EPOCH_FORMAT = "esslinger-epoch/1"
SCHED_FORMAT = "esslinger-epoch-schedule/1"
EVENTS_FORMAT = "esslinger-epoch-events/1"
MESZ = dt.timezone(dt.timedelta(hours=2))
PROVE_LOG = HERE / cs.PROVE_LOG


def epoch_dir(base: Path, n: int) -> Path:
    return base / "epochs" / f"epoch-{n}"


def iso_utc(t: float) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_mesz(t: float) -> str:
    return dt.datetime.fromtimestamp(t, MESZ).strftime("%d.%m.%Y %H:%M:%S MESZ")


def gen_schedule(seed: bytes, epoch_id: int, start_unix: int, days: int, per_day: int, lo: int, hi: int,
                 min_gap: int, day_s: int = 86400) -> dict:
    probes, slot = [], 0
    for d in range(days):
        chosen, i = [], 0
        while len(chosen) < per_day:
            if i > 100000:
                raise RuntimeError("Plan nicht erzeugbar (Parameter zu eng)")
            h = hmac.new(seed, f"{SCHED_FORMAT}|epoch={epoch_id}|day={d}|i={i}".encode(), hashlib.sha256).digest()
            off = lo + int.from_bytes(h[:8], "big") % (hi - lo)
            i += 1
            if all(abs(off - o) >= min_gap for o in chosen):
                chosen.append(off)
        for off in sorted(chosen):
            t = start_unix + d * day_s + off
            probes.append({"slot": slot, "day": d, "t_unix": t, "t_utc": iso_utc(t)})
            slot += 1
    return {"v": SCHED_FORMAT, "epoch_id": epoch_id, "start_unix": start_unix, "probes": probes}


def schedule_from_epoch(ep: dict, seed: bytes) -> dict:
    s = ep["schedule"]["params"]
    return gen_schedule(seed, ep["epoch_id"], ep["start_unix"], s["days"], s["per_day"], s["lo_s"], s["hi_s"],
                        s["min_gap_s"], s.get("day_s", 86400))


def schedule_commitment(sched: dict) -> str:
    return cs.sha256_hex(cs.canon(sched))


def load_epoch(base: Path, n: int) -> dict:
    return json.loads((epoch_dir(base, n) / f"epoch-{n}.json").read_text(encoding="utf-8"))


def seed_path(base: Path, n: int) -> Path:
    return base / "keys" / f"epoch-{n}.seed"


def load_seed(base: Path, n: int) -> bytes:
    return bytes.fromhex(seed_path(base, n).read_text().strip())


# ---------- Ereignis-Log ----------
def events_path(base: Path, n: int) -> Path:
    return epoch_dir(base, n) / "events.jsonl"


def append_event(signer, base: Path, n: int, etype: str, body: dict) -> dict:
    p = events_path(base, n)
    prev = cs.read_jsonl(p)
    rec = {"format": EVENTS_FORMAT, "epoch_id": n, "seq": len(prev), "type": etype, "ts": cs.now_utc(),
           "prev_hash": prev[-1]["record_hash"] if prev else "0" * 64, "body": body}
    signer.seal(rec)
    with open(p, "a", encoding="utf-8") as f:
        f.write(cs.canon(rec).decode("utf-8") + "\n")
        f.flush()
        os.fsync(f.fileno())
    return rec


# ---------- init ----------
def cmd_init(a):
    base = HERE
    n = a.epoch
    d = epoch_dir(base, n)
    ef = d / f"epoch-{n}.json"
    sp = seed_path(base, n)
    if ef.exists() or sp.exists() or (d / "subjects.json").exists():
        sys.exit(f"STOPP: Epoche {n} existiert schon – es wird nichts überschrieben.")
    signer = cs.Signer()
    att = cs.verify_attestations(signer.pubinfo)
    if not att["ok"]:
        sys.exit("STOPP: Bescheinigungs-Log ungültig: " + "; ".join(att["fails"]))
    start = int(a.start_unix) if a.start_unix else int(dt.datetime.now(dt.timezone.utc).timestamp())
    end = start + a.days * a.day_s
    # 1. geheimer Seed (nur Box, keys/ ist 0700 und nie in Git)
    seed = os.urandom(32)
    (base / "keys").mkdir(mode=0o700, exist_ok=True)
    fd = os.open(sp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    params = {"days": a.days, "day_s": a.day_s, "per_day": a.per_day, "lo_s": a.lo, "hi_s": a.hi, "min_gap_s": a.min_gap}
    sched = gen_schedule(seed, n, start, a.days, a.per_day, a.lo, a.hi, a.min_gap, a.day_s)
    # 2. subjects.json
    d.mkdir(parents=True, exist_ok=True)
    subjects = {"v": "esslinger-subjects/1", "epoch_id": n, "subjects": [{
        "node_id": "onyx-hannover-01", "peer_id": "12D3KooWCTqU9empQ6MayAMAgiPt9pdMb36Pv1pnqE8BduuJTwdC",
        "addr": "/ip6/202:db7e:ec7b:937e:8e9b:44a:4870:ee29/tcp/4710",
        "machine": "Onyx-PC in Hannover (Variante C, Plan 16.1)", "protocol": "/esslinger/minerproof/1.0.0",
        "probe_kind": "ping", "graded": True}],
        "not_measured": [{"node_id": "onyx-wsl", "peer_id": "12D3KooWKz7ijKoyywYBToCsdgo9R26QurwYpvMVGb77S5Dk6DJC",
                          "reason": "nicht Gegenstand der Epoche (nur IPv4, nicht über Yggdrasil erreichbar)"}]}
    with open(d / "subjects.json", "x", encoding="utf-8") as f:
        json.dump(subjects, f, ensure_ascii=False, indent=1)
    subj_sha = cs.sha256_hex((d / "subjects.json").read_bytes())
    # 3. Epochen-Datei
    ep = {
        "v": EPOCH_FORMAT, "epoch_id": n, "label": f"epoche_{n}_gewertet",
        "released": {"by": "Sven Normen Eßlinger", "at": a.released_at,
                     "decision": "Epoche freigegeben: 7 Tage, Auswertung von Hand, Schwelle 90 % Uptime; automatisch "
                                 "prüfen, höchstens 12 am Tag, Start sofort (selbst endender Prozess, M1)."},
        "start_unix": start, "end_unix": end, "start_utc": iso_utc(start), "end_utc": iso_utc(end),
        "start_mesz": iso_mesz(start), "end_mesz": iso_mesz(end), "duration_s": end - start,
        "subjects_file": "subjects.json", "subjects_sha256": subj_sha,
        "grading": {
            "scope": "NUR Erreichbarkeit/Uptime (Liveness) von onyx-hannover-01 über signierte ping-Prüfaufgaben.",
            "not_included": "Rechen- und Kapazitätsproben (R, K, Phase 3) sind NICHT Teil dieser Epoche: R = K = null.",
            "U_formula": "U = pass / (geplante Proben − verifier_outage)",
            "threshold_U": 0.90, "min_planned_probes": 42, "max_verifier_outage_share": 0.10,
            "outcomes": {"pass": "gültige, an Nonce+Blockhash gebundene Antwort innerhalb der Frist (1. oder 2. Versuch)",
                         "fail": "keine/falsche/zu späte Antwort, auch Onyx offline – zählt gegen den Knoten",
                         "verifier_outage": "Störung auf Prüferseite (Box-Kontrolle fehlgeschlagen, Prozess lief "
                                            "nicht oder > late_tolerance zu spät)"},
            "evaluation": "von Hand am Epochenende (Sven); der Prozess wertet nicht selbst aus",
            "publication": "nichts veröffentlicht – nur interne Schattenrechnung (Entwurf v8, 4a)",
            "control_quantity": "Validator-Uptime der Box-Chains (Prüfer-Eigenwert, bleibt als "
                                "probelauf_nicht_gewertet gekennzeichnet) dient nur als Kontrollgröße"},
        "probe_policy": {"kind": "ping", "deadline_s": 15, "probes_per_day": a.per_day,
                         "max_network_probes_per_day": 12,
                         "retry": "höchstens 1 Wiederholung, 60 s nach dem 1. Versuch (innerhalb 2 min), nur solange "
                                  "die Tagesobergrenze von 12 Netzproben nicht erreicht ist",
                         "late_tolerance_s": 900,
                         "control": "vor jeder Probe: beide Box-Chains per RPC erreichbar, letzter Block ≤ 60 s alt, "
                                    "Yggdrasil-Adresse der Box vorhanden; schlägt das fehl UND die Probe besteht "
                                    "nicht, gilt verifier_outage"},
        "schedule": {"format": SCHED_FORMAT, "params": params, "n_probes": len(sched["probes"]),
                     "seed_commitment": cs.sha256_hex(seed), "schedule_commitment": schedule_commitment(sched),
                     "seed_storage": f"keys/epoch-{n}.seed (Box, 0600, nie in Git) bis zur Offenlegung",
                     "reveal": f"am Epochenende: epochs/epoch-{n}/reveal.json (Seed + Plan) + Bescheinigung epoch_reveal",
                     "algorithm": "siehe epoche.py (Kopfkommentar)"},
        "maintenance": {"uptime_collector_every_s": a.maint_s, "anchor_push_every_s": a.maint_s,
                        "note": "Uptime-Sammler (--continue) und Verankerung+Push alle 12 h, zusätzlich Vorab- und Schluss-Anker"},
        "process": {"runner": "epoch_runner.py", "form": "M1: ein Hintergrundprozess (setsid/nohup), kein Cron, "
                    "kein systemd, kein Watchdog, kein Neustart", "pid_file": f"run/epoch-{n}/runner.pid",
                    "log": f"run/epoch-{n}/runner.log", "stop_file": "STOP (messserver/STOP)",
                    "hard_exit": "spätestens end_unix + 2 h beendet sich der Prozess hart"},
        "checker": {"key_id": signer.key_id, "fingerprint_sha256": signer.pubinfo["fingerprint_sha256"]},
        "anchor_repo": "github.com/digitaldesignerjazz/esslinger-mesh-nachweise (privat)",
    }
    with open(ef, "x", encoding="utf-8") as f:
        json.dump(ep, f, ensure_ascii=False, indent=1)
    for p in (ef, d / "subjects.json"):
        os.chmod(p, 0o444)
    ep_sha = cs.sha256_hex(ef.read_bytes())
    # 4. Vorab-Bescheinigung (vor der ersten Probe)
    rec = cs.append_attestation(signer, "epoch_precommit", {
        "statement": f"Vorab-Festlegung Epoche {n} durch den Prüfer (Box), VOR der ersten Probe: Epochen-Datei, "
                     "Gegenstand und Plan-Commitment (Probenzeitpunkte aus geheimem Seed, Offenlegung am Ende).",
        "label": ep["label"], "counted": True, "epoch_id": n,
        "epoch_file": f"epochs/epoch-{n}/epoch-{n}.json", "epoch_file_sha256": ep_sha,
        "subjects_sha256": subj_sha, "seed_commitment": ep["schedule"]["seed_commitment"],
        "schedule_commitment": ep["schedule"]["schedule_commitment"], "n_probes": len(sched["probes"]),
        "start_utc": ep["start_utc"], "end_utc": ep["end_utc"],
        "files": cs.snapshot(), "previous_attestation_hash": att["head"]})
    print(json.dumps({"ok": True, "epoch_file": str(ef), "epoch_file_sha256": ep_sha,
                      "start_mesz": ep["start_mesz"], "end_mesz": ep["end_mesz"], "n_probes": len(sched["probes"]),
                      "first3_mesz": [iso_mesz(p["t_unix"]) for p in sched["probes"][:3]],
                      "attestation": {"seq": rec["seq"], "record_hash": rec["record_hash"]}}, indent=1,
                     ensure_ascii=False))


# ---------- verify ----------
def verify_epoch_dir(base: Path, n: int, pub=None) -> dict:
    fails, info = [], {}
    d = epoch_dir(base, n)
    ef = d / f"epoch-{n}.json"
    pub = pub or cs.load_pub(base / "checker_pubkey.json")
    ep = json.loads(ef.read_text(encoding="utf-8"))
    ep_sha = cs.sha256_hex(ef.read_bytes())
    if cs.sha256_hex((d / "subjects.json").read_bytes()) != ep["subjects_sha256"]:
        fails.append("subjects.json passt nicht zum Hash in der Epochen-Datei")
    att = cs.verify_attestations(pub, base / "attest" / "attestations.jsonl")
    fails += att["fails"]
    pre = [r for r in att["records"] if r["type"] == "epoch_precommit" and r["body"].get("epoch_id") == n]
    if len(pre) != 1:
        fails.append(f"erwartet genau eine Vorab-Bescheinigung für Epoche {n}, gefunden {len(pre)}")
        return {"ok": False, "fails": fails}
    pre = pre[0]
    b = pre["body"]
    for k, v in (("epoch_file_sha256", ep_sha), ("seed_commitment", ep["schedule"]["seed_commitment"]),
                 ("schedule_commitment", ep["schedule"]["schedule_commitment"]),
                 ("subjects_sha256", ep["subjects_sha256"])):
        if b.get(k) != v:
            fails.append(f"Vorab-Bescheinigung: {k} passt nicht")
    pre_ts = pre["ts"]
    info["precommit"] = {"seq": pre["seq"], "record_hash": pre["record_hash"], "ts": pre_ts}
    subj = json.loads((d / "subjects.json").read_text(encoding="utf-8"))["subjects"][0]
    # Ereignis-Log
    evs = cs.read_jsonl(events_path(base, n))
    prev = "0" * 64
    for i, r in enumerate(evs):
        if r.get("format") != EVENTS_FORMAT or r.get("seq") != i or r.get("prev_hash") != prev or r.get("epoch_id") != n:
            fails.append(f"Ereignis {i}: Kette/Format falsch")
        v = cs.verify_record(r, pub)
        if not (v["record_hash_ok"] and v["checker_sig_ok"]):
            fails.append(f"Ereignis {i}: Hash oder Prüfer-Signatur ungültig")
        if r["ts"] < pre_ts:
            fails.append(f"Ereignis {i}: liegt vor der Vorab-Bescheinigung")
        prev = r.get("record_hash")
    # Prüfaufgaben-Log: Proben der Epoche
    plog = base / cs.PROVE_LOG
    prove = {r["seq"]: r for r in cs.read_jsonl(plog)} if plog.exists() else {}
    label = ep["label"]
    epoch_recs = {s for s, r in prove.items() if r.get("status") == label}
    referenced, outcomes, slots_seen = set(), {}, {}
    for r in evs:
        if r["type"] != "probe":
            continue
        pb = r["body"]
        if pb["slot"] in slots_seen:
            fails.append(f"Slot {pb['slot']} doppelt im Ereignis-Log")
        slots_seen[pb["slot"]] = pb
        outcomes[pb["outcome"]] = outcomes.get(pb["outcome"], 0) + 1
        for at in pb.get("attempts", []):
            s = at.get("evidence_seq")
            if s is None:
                continue
            pr = prove.get(s)
            if pr is None or pr["record_hash"] != at.get("evidence_record_hash"):
                fails.append(f"Slot {pb['slot']}: Prüfaufgaben-Datensatz {s} fehlt oder passt nicht")
                continue
            if pr.get("status") != label or pr.get("expected_peer_id") != subj["peer_id"] \
                    or pr.get("target_addr") != subj["addr"]:
                fails.append(f"Slot {pb['slot']}: Datensatz {s} hat falschen Status/Gegenstand")
            if pr["result"] != at.get("result"):
                fails.append(f"Slot {pb['slot']}: Ergebnis im Ereignis ≠ Prüfaufgaben-Log")
            issued = dt.datetime.strptime(pr["challenge"]["issued_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=dt.timezone.utc).timestamp()
            if not (pb["scheduled_unix"] - 5 <= issued <= pb["scheduled_unix"] + ep["probe_policy"]["late_tolerance_s"] + 180):
                fails.append(f"Slot {pb['slot']}: Probe nicht zum geplanten Zeitpunkt ausgestellt")
            referenced.add(s)
        want = "pass" if any(at.get("result") == "pass" for at in pb.get("attempts", [])) else None
        if want and pb["outcome"] != "pass":
            fails.append(f"Slot {pb['slot']}: bestandene Probe nicht als pass gewertet")
        if not want and pb["outcome"] == "pass":
            fails.append(f"Slot {pb['slot']}: pass ohne bestandenen Versuch")
    for r in evs:
        if r["type"] == "orphan_records":
            for s in r["body"]["evidence_seqs"]:
                if s in referenced:
                    fails.append(f"Datensatz {s} zugleich Slot-Probe und verwaist")
                referenced.add(s)
    stray = epoch_recs - referenced
    if stray:
        fails.append(f"gewertete Prüfaufgaben ohne Plan-Slot im Ereignis-Log: {sorted(stray)}")
    # Offenlegung
    rv = d / "reveal.json"
    info["revealed"] = rv.exists()
    if rv.exists():
        r = json.loads(rv.read_text(encoding="utf-8"))
        seed = bytes.fromhex(r["seed_hex"])
        if cs.sha256_hex(seed) != ep["schedule"]["seed_commitment"]:
            fails.append("offengelegter Seed passt nicht zum seed_commitment")
        sched = schedule_from_epoch(ep, seed)
        if schedule_commitment(sched) != ep["schedule"]["schedule_commitment"] or sched != r["schedule"]:
            fails.append("Plan aus Seed passt nicht zum schedule_commitment")
        byslot = {p["slot"]: p for p in sched["probes"]}
        for s, pb in slots_seen.items():
            if s not in byslot or byslot[s]["t_unix"] != pb["scheduled_unix"]:
                fails.append(f"Slot {s}: Zeitpunkt passt nicht zum offengelegten Plan")
        missing = [p["slot"] for p in sched["probes"] if p["slot"] not in slots_seen and p["t_unix"] < r.get("revealed_unix", 0)]
        if missing and not r.get("stopped_early"):
            fails.append(f"geplante Slots ohne Ergebnis: {missing[:10]}")
        info["schedule_verified"] = not any("Plan" in f or "Seed" in f for f in fails)
    info.update({"events": len(evs), "probe_slots_recorded": len(slots_seen), "outcomes": outcomes,
                 "n_planned": ep["schedule"]["n_probes"], "label": label})
    return {"ok": not fails, "fails": fails, **info}


def unreferenced_epoch_records(base: Path, n: int) -> list:
    ep = load_epoch(base, n)
    plog = base / cs.PROVE_LOG
    recs = [r["seq"] for r in cs.read_jsonl(plog) if r.get("status") == ep["label"]] if plog.exists() else []
    ref = set()
    for r in cs.read_jsonl(events_path(base, n)):
        if r["type"] == "probe":
            ref |= {a.get("evidence_seq") for a in r["body"].get("attempts", [])}
        elif r["type"] == "orphan_records":
            ref |= set(r["body"]["evidence_seqs"])
    return [s for s in recs if s not in ref]


def cmd_verify(a):
    base = Path(a.base).resolve()
    res = {}
    ok = True
    for ef in sorted((base / "epochs").glob("epoch-*/epoch-*.json")):
        n = int(ef.stem.split("-")[1])
        r = verify_epoch_dir(base, n)
        res[f"epoch-{n}"] = r
        ok &= r["ok"]
    print(json.dumps({"ok": ok, "epochs": res}, indent=1, ensure_ascii=False))
    sys.exit(0 if ok else 1)


def cmd_summary(a):
    base = Path(a.base).resolve()
    ep = load_epoch(base, a.epoch)
    evs = [r for r in cs.read_jsonl(events_path(base, a.epoch)) if r["type"] == "probe"]
    c = {"pass": 0, "fail": 0, "verifier_outage": 0}
    for r in evs:
        c[r["body"]["outcome"]] += 1
    planned = ep["schedule"]["n_probes"]
    denom = planned - c["verifier_outage"]
    print(json.dumps({"epoch_id": a.epoch, "label": ep["label"], "planned": planned, "recorded": len(evs), **c,
                      "U_so_far_over_recorded": round(c["pass"] / max(1, len(evs) - c["verifier_outage"]), 4),
                      "U_formula_at_end": f"pass / ({planned} − verifier_outage) = {c['pass']}/{denom}",
                      "note": "Hilfszählung – die Wertung macht Sven von Hand am Epochenende."}, indent=1,
                     ensure_ascii=False))


def do_reveal(base: Path, n: int, signer, stopped_early: bool, reason: str) -> dict:
    ep = load_epoch(base, n)
    seed = load_seed(base, n)
    sched = schedule_from_epoch(ep, seed)
    if schedule_commitment(sched) != ep["schedule"]["schedule_commitment"]:
        raise SystemExit("STOPP: Seed passt nicht zum Commitment")
    rv = epoch_dir(base, n) / "reveal.json"
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    doc = {"v": "esslinger-epoch-reveal/1", "epoch_id": n, "seed_hex": seed.hex(),
           "seed_commitment": ep["schedule"]["seed_commitment"],
           "schedule_commitment": ep["schedule"]["schedule_commitment"], "schedule": sched,
           "revealed_utc": iso_utc(now), "revealed_unix": int(now), "stopped_early": stopped_early, "reason": reason}
    with open(rv, "x", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    os.chmod(rv, 0o444)
    att = cs.verify_attestations(signer.pubinfo)
    return cs.append_attestation(signer, "epoch_reveal", {
        "statement": f"Offenlegung Plan-Seed Epoche {n} (Prüfer, Box).", "label": ep["label"], "counted": True,
        "epoch_id": n, "reveal_file_sha256": cs.sha256_hex(rv.read_bytes()), "stopped_early": stopped_early,
        "reason": reason, "files": cs.snapshot(), "previous_attestation_hash": att["head"]})


def cmd_reveal(a):
    signer = cs.Signer()
    r = do_reveal(HERE, a.epoch, signer, True, a.reason)
    print(json.dumps({"ok": True, "attestation_seq": r["seq"], "record_hash": r["record_hash"]}, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("init")
    p.add_argument("--epoch", type=int, required=True)
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--per-day", type=int, default=10)
    p.add_argument("--lo", type=int, default=600)
    p.add_argument("--hi", type=int, default=86100)
    p.add_argument("--min-gap", type=int, default=1800)
    p.add_argument("--start-unix", type=int)
    p.add_argument("--day-s", type=int, default=86400, help="nur für Tests ≠ 86400")
    p.add_argument("--maint-s", type=int, default=43200)
    p.add_argument("--released-at", default="2026-10-04T01:15:00+02:00")
    p = sp.add_parser("verify")
    p.add_argument("--base", default=str(HERE))
    p = sp.add_parser("summary")
    p.add_argument("--epoch", type=int, default=1)
    p.add_argument("--base", default=str(HERE))
    p = sp.add_parser("reveal")
    p.add_argument("--epoch", type=int, required=True)
    p.add_argument("--reason", required=True)
    a = ap.parse_args()
    {"init": cmd_init, "verify": cmd_verify, "summary": cmd_summary, "reveal": cmd_reveal}[a.cmd](a)


if __name__ == "__main__":
    main()
