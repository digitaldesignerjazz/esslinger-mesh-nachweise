# Esslinger Mesh – Nachweise (Anker-Repo, öffentlich seit 04.10.2026 01:18 MESZ, Entscheidung Sven)

**Status:** Alles bis 04.10.2026 01:30 MESZ ist Probelauf (nicht gewertet). **Epoche 1 (`epoche_1_gewertet`) läuft vom 04.10.2026 01:30:08 bis 11.10.2026 01:30:08 MESZ** – von Sven am 04.10. um 01:15 freigegeben. Gewertet wird nur die Erreichbarkeit (Uptime) von `onyx-hannover-01` über signierte Prüfaufgaben; Rechen- und Kapazitätsproben (Phase 3) sind nicht Teil dieser Epoche. Die Auswertung macht Sven von Hand am Epochenende, es ist nur eine interne Schattenrechnung.

**Öffentlich seit 04.10.2026 01:18 MESZ (Svens Entscheidung).** Vor jedem Commit und Push läuft eine Geheimnis-Prüfung (Dateinamen, Muster, Abgleich mit dem Prüferschlüssel und mit noch nicht offengelegten Epochen-Seeds).

Dieses Repo ist die **Verankerung** des Messservers (Plan `messserver-uptime-nachweis-plan-20261004.md`, Abschnitt 10 „V3“ und 16.1). Es enthält nur Nachweise und Prüfskripte, **keine Geheimnisse**: keinen Prüfer-Geheimschlüssel, kein `mesh.key`, keine Wallet- oder Validator-Schlüssel. Commits kommen von `anker.py` auf der Box – von Hand oder, nur während Epoche 1, vom selbst endenden Epochen-Prozess höchstens alle 12 h. Der Push-Zeitpunkt bei GitHub ist ein Zeitbeleg außerhalb der Box: Was hier gepusht ist, kann die Box später nicht mehr unbemerkt umschreiben.

## Wer misst wen
- **Gemessen:** `onyx-hannover-01` (Onyx-PC in Hannover), PeerId `12D3KooWCTqU9empQ6MayAMAgiPt9pdMb36Pv1pnqE8BduuJTwdC`, Yggdrasil `202:db7e:ec7b:937e:8e9b:44a:4870:ee29`, TCP 4710.
- **Prüfer:** die Box. Sie schickt Prüfaufgaben (Nonce + aktueller Blockhash), Onyx unterschreibt mit seinem Knotenschlüssel.
- **Validator-Uptime** der Box-Chains `nexus-xcoin-1` und `nexus-qcoin-1`: aus den Blockdaten, jede Commit-Signatur nachgerechnet. Das ist ein **Prüfer-Eigenwert** (die Box prüft ihre eigenen Validatoren) und zählt nicht als unabhängige Messung.

## Prüferschlüssel
`checker_pubkey.json` ist der öffentliche Ed25519-Schlüssel des Prüfers. Jeder neue Datensatz trägt `checker_sig` = Ed25519 über
`"esslinger-checker-v1\0" || record_hash` (record_hash = SHA-256 über kanonisches JSON ohne `record_hash`/`checker_sig`).
Ältere Datensätze aus der Zeit vor dem Schlüssel wurden **nicht umgeschrieben**. Sie sind über die signierte **Genesis-Bescheinigung** (`attest/attestations.jsonl`, Eintrag 0) erfasst, die ihre Köpfe und Datei-Hashes festhält. Jeder Anker-Commit hängt eine weitere signierte Bescheinigung an.

## Inhalt
| Pfad | Inhalt |
|---|---|
| `checker_pubkey.json` | öffentlicher Prüferschlüssel + Fingerabdruck |
| `attest/attestations.jsonl` | Genesis- und Anker-Bescheinigungen (Hash-Kette, signiert) |
| `onyx-prove/log/evidence.jsonl` | Prüfaufgaben an onyx-hannover-01 (Challenge, signierte Antwort, Frischemarken) |
| `onyx-prove/raw/*.json` | Rohdaten zu jedem Prüfaufgaben-Datensatz |
| `log/*.jsonl` | Validator-Uptime-Logs (volle Header und Commits, Hash-Kette, Merkle-Wurzel) |
| `nachweise/*.json` | Nachweis-Dateien je Lauf (+ `.verify.json` = Prüfbericht) |
| `epochs/epoch-1/epoch-1.json`, `subjects.json` | Festlegung Epoche 1 (vor der ersten Probe verankert): Fenster, Gegenstand, Regeln, `seed_commitment`, `schedule_commitment` |
| `epochs/epoch-1/events.jsonl` | Ereignis-Log des Epochen-Prozesses (je Plan-Slot ein Ergebnis pass/fail/verifier_outage, Wartung, Start/Stopp; Hash-Kette, signiert) |
| `epochs/epoch-1/reveal.json` | erst am Epochenende: offengelegter Seed + Plan (nachrechenbar mit `epoche.py verify`) |
| `epoche.py`, `epoch_runner.py` | Plan-Algorithmus, Nachprüfung, Epochen-Prozess |
| `verify_alles.py`, `verify_epoch.py`, `onyx-prove/verify_prove.py`, `mp_common.py`, `checker_sig.py`, `onyx-prove/prove_common.py` | Prüfskripte |

## Selbst nachprüfen (ohne Box, ohne Geheimnis)
```bash
pip install cryptography        # einzige Abhängigkeit
python3 verify_alles.py         # Exit-Code 0 = alles OK
```
Geprüft werden: Bescheinigungs-Kette und Prüfer-Signaturen, dass alle bescheinigten Log-Anfänge unverändert sind, jede Antwort-Signatur von Onyx (Schlüssel aus der PeerId) samt Bindung an Nonce und Blockhash, jede Validator-Commit-Signatur, Header-Hashes, lückenlose Höhen, der Anschluss jedes Laufs an den vorherigen und für Epochen: Vorab-Bescheinigung, Ereignis-Log und (nach der Offenlegung) Seed und Probenplan.

## Grenzen (ehrlich)
- Prüfer und Gemessener gehören demselben Betreiber. Der Schlüssel beweist, **wer** geantwortet hat, nicht **wo** der Rechner steht.
- Zeitangaben stammen von der Box-Uhr und den eigenen Chains. Belastbar außerhalb der Box ist nur der Push-Zeitpunkt bei GitHub.
- Die Validator-Uptime ist ein Prüfer-Eigenwert.
