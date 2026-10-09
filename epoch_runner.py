#!/usr/bin/env python3
"""Selbst endender Epochen-Prozess (M1, Plan Abschnitt 14) – von Sven für Epoche 1 ausdrücklich freigegeben (04.10.2026 01:15).

EIN Prozess für GENAU EINE Epoche. Kein Cron, kein systemd-Timer, kein Watchdog, kein Neustart.
  - schläft bis zu jedem vorab festgelegten Zeitpunkt (Plan aus keys/epoch-<n>.seed, Commitment vorab verankert)
  - pro Zeitpunkt eine ping-Prüfaufgabe an den Gegenstand (onyx-node prove-Protokoll, Antwort signiert Onyx,
    Datensatz signiert der Prüfer); nicht bestanden -> höchstens EINE Wiederholung nach 60 s (Tagesgrenze 12 Netzproben)
  - alle 12 h: Validator-Uptime inkrementell (Kontrollgröße) + Prüfung + Verankerung + Push (mit Geheimnis-Prüfung)
  - endet von selbst am Epochenende: letzte Wartung, Seed-Offenlegung, Schluss-Anker, Exit
  - endet sofort, wenn die Datei messserver/STOP existiert (oder bei SIGTERM/SIGINT); hart spätestens Ende + 2 h
Keine Transaktion, kein Wallet-, Validator- oder Mesh-Schlüssel, kein laufender Knoten wird angefasst.

Start (einmal):  setsid nohup python3 epoch_runner.py --epoch 1 >> run/epoch-1/runner.out 2>&1 < /dev/null &
Stop:            touch …/messserver/STOP (für Stopp über Neustart hinaus: echo Grund > STOP) (oder: kill $(cat run/epoch-1/runner.pid))
"""
import argparse, datetime as dt, fcntl, json, os, signal, subprocess, sys, threading, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import checker_sig as cs  # noqa: E402
import epoche  # noqa: E402

STOP_FILE = HERE / "STOP"
CHAINS = {"nexus-xcoin-1": "127.0.0.1:36657", "nexus-qcoin-1": "127.0.0.1:37657"}
RETRY_DELAY_S = 60
MAINT_GUARD_S = 25 * 60   # Wartung nur, wenn die nächste Probe mindestens 25 min entfernt ist
HARD_EXTRA_S = 2 * 3600
_term = {"sig": None}


def log(msg):
    line = f"{dt.datetime.now(epoche.MESZ).strftime('%Y-%m-%d %H:%M:%S MESZ')} {msg}"
    with open(LOGF, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run(cmd, timeout):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", PYTHONUNBUFFERED="1")
    try:
        p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") if isinstance(e.stdout, str) else "", f"Zeitüberschreitung nach {timeout} s"


def control_check():
    """Prüferseite gesund? Beide Chains erreichbar, letzter Block <= 60 s alt, Yggdrasil-Adresse der Box vorhanden."""
    res, ok = {}, True
    for cid, hp in CHAINS.items():
        try:
            with urllib.request.urlopen(f"http://{hp}/status", timeout=5) as r:
                si = json.load(r)["result"]["sync_info"]
            bt = dt.datetime.fromisoformat(si["latest_block_time"][:26].rstrip("Z") + "+00:00")
            age = (dt.datetime.now(dt.timezone.utc) - bt).total_seconds()
            res[cid] = {"height": int(si["latest_block_height"]), "block_age_s": round(age, 1)}
            ok &= age <= 60
        except Exception as e:
            res[cid] = {"error": str(e)[:200]}
            ok = False
    ygg = False
    try:
        for line in open("/proc/net/if_inet6"):
            if line.split()[0][:2] in ("02", "03"):  # 200::/7 = Yggdrasil
                ygg = True
    except Exception:
        pass
    res["box_yggdrasil_addr_present"] = ygg
    return ok and ygg, res


def done_state(evs):
    slots = {r["body"]["slot"] for r in evs if r["type"] == "probe"}
    maint = {r["body"]["k"] for r in evs if r["type"] == "maintenance"}
    attempts_by_day = {}
    for r in evs:
        if r["type"] == "probe":
            d = r["body"]["day"]
            attempts_by_day[d] = attempts_by_day.get(d, 0) + len([a for a in r["body"]["attempts"] if a.get("sent")])
    return slots, maint, attempts_by_day


def stop_requested():
    return STOP_FILE.exists() or _term["sig"] is not None


def sleep_until(t_target):
    """Schläft in 1-s-Schritten; True = Ziel erreicht, False = Stopp angefordert."""
    while True:
        if stop_requested():
            return False
        rem = t_target - time.time()
        if rem <= 0:
            return True
        time.sleep(min(1.0, rem))


def one_attempt(ep_file, subj, slot, attempt, note):
    cmd = [sys.executable, "onyx-prove/run_prove.py", "--label", subj["node_id"], "--target", subj["addr"],
           "--expect", subj["peer_id"], "--status", EP["label"], "--epoch-file", str(ep_file),
           "--epoch-slot", str(slot), "--attempt", str(attempt), "--note", note]
    t0 = time.time()
    rc, out, err = run(cmd, timeout=120)
    a = {"attempt": attempt, "started_utc": epoche.iso_utc(t0), "rc": rc, "sent": False}
    try:
        d = json.loads(out)
        a.update({"sent": True, "evidence_seq": d["seq"], "evidence_record_hash": d["record_hash"],
                  "result": d["result"], "challenge_rtt_ms": d.get("challenge_rtt_ms"),
                  "connect_ms": d.get("connect_ms"), "checker_error": d.get("checker_error"),
                  "node_error": d.get("node_error")})
    except Exception:
        a.update({"result": "no_record", "error": (err or out)[-400:]})
    return a


def do_probe(p, attempts_today, ep_file, subj):
    slot, sched_t = p["slot"], p["t_unix"]
    late = time.time() - sched_t
    body = {"slot": slot, "day": p["day"], "scheduled_unix": sched_t, "scheduled_utc": p["t_utc"],
            "started_late_s": round(late, 1), "attempts": []}
    if late > EP["probe_policy"]["late_tolerance_s"]:
        body.update({"outcome": "verifier_outage", "reason": "Prozess lief nicht / Zeitpunkt verpasst (Prüferseite)"})
        return body
    ctl_ok, ctl = control_check()
    body["control"] = ctl
    a1 = one_attempt(ep_file, subj, slot, 1, f"epoche-{EP['epoch_id']} slot {slot} versuch 1")
    body["attempts"].append(a1)
    used = attempts_today + (1 if a1["sent"] else 0)
    if a1.get("result") != "pass" and not stop_requested():
        if used < EP["probe_policy"]["max_network_probes_per_day"]:
            if sleep_until(time.time() + RETRY_DELAY_S):
                ctl_ok2, ctl2 = control_check()
                body["control_retry"] = ctl2
                ctl_ok = ctl_ok and ctl_ok2
                body["attempts"].append(one_attempt(ep_file, subj, slot, 2, f"epoche-{EP['epoch_id']} slot {slot} versuch 2"))
        else:
            body["retry_skipped"] = "Tagesgrenze von 12 Netzproben erreicht"
    if any(a.get("result") == "pass" for a in body["attempts"]):
        body["outcome"] = "pass"
    elif not ctl_ok or all(a.get("result") == "no_record" for a in body["attempts"]):
        body["outcome"], body["reason"] = "verifier_outage", "Kontrolle der Prüferseite fehlgeschlagen"
    else:
        body["outcome"] = "fail"
    return body


def maintenance(k, final=False):
    body = {"k": k, "final": final, "started_utc": cs.now_utc()}
    run_id = f"epoche{EP['epoch_id']}-kontrolle-{dt.datetime.now(epoche.MESZ).strftime('%Y%m%dT%H%M%S')}"
    args = [sys.executable, "collect_validator_uptime.py", "--probelauf", "--continue", "--epoch", run_id]
    for cid, hp in CHAINS.items():
        args += ["--chain", f"{cid}={hp}"]
    rc, out, err = run(args, timeout=3600)
    body["collector"] = {"run_id": run_id, "rc": rc, "tail": (out or err)[-600:]}
    nw = HERE / "nachweise" / f"{run_id}.json"
    if nw.exists():
        rpc = []
        for cid, hp in CHAINS.items():
            rpc += ["--rpc", f"{cid}={hp}"]
        rc2, out2, err2 = run([sys.executable, "verify_epoch.py", str(nw), *rpc, "--rpc-check", "20",
                               "--report", f"nachweise/{run_id}.verify.json"], timeout=3600)
        body["verify_epoch_rc"] = rc2
        try:
            os.chmod(HERE / "nachweise" / f"{run_id}.verify.json", 0o444)
        except OSError:
            pass
    log(f"Wartung k={k}: Sammler rc={rc}, verify={body.get('verify_epoch_rc')}")
    return body


def anchor(note):
    rc, out, err = run([sys.executable, "anker.py", "--repo", str(HERE.parent / "messserver-anker"), "--push",
                        "--label", EP["label"], "--note", note], timeout=3600)
    res = {"rc": rc}
    try:
        d = json.loads(out)
        res.update({"commit": d.get("commit"), "pushed": d.get("pushed"),
                    "attestation_seq": (d.get("attestation") or {}).get("seq")})
    except Exception:
        res["error"] = (err or out)[-600:]
    log(f"Anker ({note}): {res}")
    return res


def main():
    global EP, LOGF
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--epoch", type=int, required=True)
    a = ap.parse_args()
    n = a.epoch
    ep_file = epoche.epoch_dir(HERE, n) / f"epoch-{n}.json"
    EP = json.loads(ep_file.read_text(encoding="utf-8"))
    rdir = HERE / "run" / f"epoch-{n}"
    rdir.mkdir(parents=True, exist_ok=True)
    LOGF = rdir / "runner.log"
    lockf = open(rdir / "runner.lock", "a")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("STOPP: ein Epochen-Prozess läuft schon.")
    if STOP_FILE.exists():
        sys.exit(f"STOPP: {STOP_FILE} existiert – erst entfernen (bewusste Entscheidung).")
    end = EP["end_unix"]
    if time.time() >= end:
        sys.exit("Epoche ist schon zu Ende.")
    # Vorab-Festlegung prüfen, bevor irgendetwas gemessen wird
    signer = cs.Signer()
    v = epoche.verify_epoch_dir(HERE, n, signer.pubinfo)
    if not v["ok"]:
        sys.exit("STOPP: Epochen-Prüfung schlägt fehl: " + "; ".join(v["fails"]))
    seed = epoche.load_seed(HERE, n)
    sched = epoche.schedule_from_epoch(EP, seed)
    if epoche.schedule_commitment(sched) != EP["schedule"]["schedule_commitment"]:
        sys.exit("STOPP: Seed passt nicht zum vorab verankerten Commitment.")
    subj = json.loads((ep_file.parent / EP["subjects_file"]).read_text(encoding="utf-8"))["subjects"][0]
    (rdir / "runner.pid").write_text(f"{os.getpid()}\n")

    def on_sig(s, _f):
        _term["sig"] = s
    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    def hard_exit():
        log("HARTES ENDE: Epochenende + 2 h überschritten – Prozess beendet sich.")
        os._exit(3)
    t = threading.Timer(max(1, end + HARD_EXTRA_S - time.time()), hard_exit)
    t.daemon = True
    t.start()

    evs = cs.read_jsonl(epoche.events_path(HERE, n))
    append = lambda typ, body: epoche.append_event(signer, HERE, n, typ, body)  # noqa: E731
    append("runner_start", {"pid": os.getpid(), "resume": bool(evs), "end_utc": EP["end_utc"],
                            "stop_file": str(STOP_FILE), "precommit": v["precommit"]})
    log(f"Start Epoche {n} (PID {os.getpid()}), Ende {EP['end_mesz']}, {len(sched['probes'])} Proben geplant")
    # Datensätze der Epoche ohne Slot-Ereignis (z. B. nach kill -9 mitten in einer Probe) offen ausweisen, nicht werten
    orphans = epoche.unreferenced_epoch_records(HERE, n)
    if orphans:
        append("orphan_records", {"evidence_seqs": orphans, "note": "ohne Slot-Ereignis, zählen nicht"})
        log(f"Verwaiste Datensätze ausgewiesen: {orphans}")
    maint_every = EP["maintenance"]["uptime_collector_every_s"]
    n_maint = int((end - EP["start_unix"]) // maint_every)   # k = 1..n_maint-1 regulär, k = n_maint am Ende
    reason = None
    while True:
        evs = cs.read_jsonl(epoche.events_path(HERE, n))
        slots_done, maint_done, att_day = done_state(evs)
        now = time.time()
        if stop_requested():
            reason = "STOP-Datei" if STOP_FILE.exists() else f"Signal {_term['sig']}"
            break
        if now >= end:
            reason = "Epochenende"
            break
        pending = [p for p in sched["probes"] if p["slot"] not in slots_done and p["t_unix"] < end]
        nxt = pending[0] if pending else None
        if nxt and nxt["t_unix"] <= now:
            body = do_probe(nxt, att_day.get(nxt["day"], 0), ep_file, subj)
            append("probe", body)
            log(f"Probe slot {nxt['slot']} ({epoche.iso_mesz(nxt['t_unix'])}): {body['outcome']} "
                f"– Versuche {[x.get('result') for x in body['attempts']]}")
            continue
        due = [k for k in range(1, n_maint) if k not in maint_done and EP["start_unix"] + k * maint_every <= now]
        if due and (nxt is None or nxt["t_unix"] - now >= MAINT_GUARD_S):
            k = due[0]
            body = maintenance(k)
            body["anchor"] = anchor(f"Epoche {n} Wartung k={k}")
            append("maintenance", body)
            continue
        cands = [end]
        if nxt:
            cands.append(nxt["t_unix"])
        open_k = [k for k in range(1, n_maint) if k not in maint_done]
        if open_k and not due:
            cands.append(EP["start_unix"] + open_k[0] * maint_every)
        wake = min(cands)
        sleep_until(wake if wake > now else now + 1)
    if reason == "Epochenende":
        # geplante Zeitpunkte vor dem Ende, die nicht mehr drankamen (Prozess belegt): Prüferseite, kein fail
        evs = cs.read_jsonl(epoche.events_path(HERE, n))
        slots_done, _, _ = done_state(evs)
        for p in sched["probes"]:
            if p["slot"] not in slots_done and p["t_unix"] < end:
                append("probe", {"slot": p["slot"], "day": p["day"], "scheduled_unix": p["t_unix"],
                                 "scheduled_utc": p["t_utc"], "started_late_s": round(time.time() - p["t_unix"], 1),
                                 "attempts": [], "outcome": "verifier_outage",
                                 "reason": "vor Epochenende nicht mehr drangekommen (Prozess belegt)"})
                log(f"Slot {p['slot']} nicht mehr drangekommen -> verifier_outage")
        body = maintenance(n_maint, final=True)
        evs = cs.read_jsonl(epoche.events_path(HERE, n))
        c = {}
        for r in evs:
            if r["type"] == "probe":
                c[r["body"]["outcome"]] = c.get(r["body"]["outcome"], 0) + 1
        body["outcome_counts"] = c
        append("epoch_end", body)
        try:
            rv = epoche.do_reveal(HERE, n, signer, False, "Epochenende")
            log(f"Seed offengelegt, Bescheinigung seq {rv['seq']}")
        except BaseException as e:  # noqa: BLE001
            log(f"Offenlegung fehlgeschlagen: {e}")
        anchor(f"Epoche {n} Ende + Offenlegung")
    else:
        append("runner_stop", {"reason": reason, "pid": os.getpid(),
                               "note": "Vorzeitig beendet. Seed bleibt geheim; Offenlegung von Hand: "
                                       f"python3 epoche.py reveal --epoch {n} --reason '...'"})
        log(f"Gestoppt: {reason} (kein Neustart, kein Push)")
    log("Ende des Prozesses.")
    (rdir / "runner.status").write_text(f"beendet {cs.now_utc()} ({reason}), PID {os.getpid()}\n")


if __name__ == "__main__":
    main()
