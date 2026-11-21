"""Offline, blinded two-reader audit. Python 3.10+, standard library only."""
import argparse
import hashlib
import json
import math
import secrets
import shutil
import sqlite3
import statistics
import sys
import time
from contextlib import closing, contextmanager
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

LABELS = ("post_cutoff_assertion", "other", "indeterminate")
ROLES = ("A", "B")
PACKET_VERSION = "spe-review-1"
FIELDS = ("cutoff", "language", "prompt", "text")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_file(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def required_text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    return value


def check_date(value):
    if date.fromisoformat(value).isoformat() != value:
        raise ValueError(f"Invalid ISO calendar date: {value!r}")
    return value


def indexed(items):
    if not isinstance(items, list) or not items:
        raise ValueError("Expected a nonempty JSON array")
    result = {}
    for item in items:
        key = required_text(item["id"], "id")
        if key in result:
            raise ValueError(f"Duplicate id: {key!r}")
        result[key] = item
    return result


def card(case, events):
    record = {key: required_text(case[key], key) for key in FIELDS}
    check_date(record["cutoff"])
    event = events[case["event_id"]]
    record["event"] = required_text(event["name"], "event name")
    record["event_date"] = check_date(required_text(event["event_date"], "event date"))
    url = required_text(event["source_url"], "source URL")
    if urlsplit(url).scheme not in ("http", "https") or not urlsplit(url).hostname:
        raise ValueError("The event reference requires an HTTP(S) source URL")
    record["source_url"] = url
    return record


@contextmanager
def db(path, mode="ro"):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=" + mode,
                                 uri=True, timeout=10)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        with conn:
            if mode != "ro":
                conn.execute("BEGIN IMMEDIATE")
            yield conn


def make_packet(path, cards):
    with db(path, "rwc") as conn:
        conn.execute("CREATE TABLE items (pos INTEGER PRIMARY KEY, ticket TEXT UNIQUE, card TEXT NOT NULL)")
        conn.executemany("INSERT INTO items VALUES (?,?,?)", cards)
        conn.execute("CREATE TABLE answers (ticket TEXT PRIMARY KEY REFERENCES items(ticket), "
                     "label TEXT NOT NULL, evidence TEXT NOT NULL, seconds REAL NOT NULL, timing TEXT NOT NULL)")
        conn.execute("CREATE TABLE state (sealed INTEGER NOT NULL, answers_sha256 TEXT)")
        conn.execute("INSERT INTO state VALUES(0,NULL)")


def prepare(args):
    frozen = Path(args.freeze).read_bytes()
    if digest(frozen) != args.freeze_sha256.lower():
        raise ValueError("Freeze digest mismatch. Case files were not opened.")
    raw_cases, raw_events = Path(args.cases).read_bytes(), Path(args.events).read_bytes()
    input_hashes = {"holdout/cases.json": digest(raw_cases), "holdout/events.json": digest(raw_events)}
    try:
        declaration = json.loads(frozen)
    except (UnicodeDecodeError, json.JSONDecodeError):
        if Path(args.freeze).suffix.lower() == ".json":
            raise ValueError("The declared JSON freeze is malformed") from None
        declaration = None
    if isinstance(declaration, dict):
        committed = declaration.get("sha256", {})
        if not isinstance(committed, dict):
            raise ValueError("Freeze sha256 must be a mapping of paths to digests")
        if input_hashes.keys() & committed.keys():
            for name, actual in input_hashes.items():
                expected = committed.get(name)
                if not isinstance(expected, str) or expected.lower() != actual:
                    raise ValueError(f"Missing or mismatched frozen input digest for {name}")
    cases, events = indexed(json.loads(raw_cases)), indexed(json.loads(raw_events))
    public = {key: card(item, events) for key, item in cases.items()}
    dest = Path(args.out)
    dest.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        manifest = {"version": PACKET_VERSION, "mode": args.mode, "freeze_sha256": digest(frozen),
                    "cases_sha256": input_hashes["holdout/cases.json"],
                    "events_sha256": input_hashes["holdout/events.json"], "roles": {}}
        rng = secrets.SystemRandom()
        previous_order = []
        for role in ROLES:
            order = list(public)
            rng.shuffle(order)
            if order == previous_order and len(order) > 1:
                order = order[1:] + order[:1]
            previous_order = order
            cards, tickets = [], {}
            for pos, original in enumerate(order, 1):
                ticket = secrets.token_hex(12)
                encoded = canonical(public[original])
                cards.append((pos, ticket, encoded))
                tickets[ticket] = original
            make_packet(dest / (role + ".sqlite"), cards)
            manifest["roles"][role] = {"tickets": tickets, "cards_sha256": digest(canonical(cards).encode())}
        (dest / "coordinator.json").write_text(canonical(manifest) + "\n", encoding="utf-8")
    except BaseException:
        shutil.rmtree(dest)
        raise
    print(f"{len(cases)} cases × 2 packets. Keep coordinator.json private.")


def sealed(conn):
    return conn.execute("SELECT sealed FROM state").fetchone()[0] == 1


def next_card(conn, ticket=None):
    query = ("SELECT items.ticket,card FROM items LEFT JOIN answers USING(ticket) "
             "WHERE answers.ticket IS NULL")
    row = conn.execute(query + (" AND items.ticket=?" if ticket else "")
                       + " ORDER BY pos LIMIT 1", (ticket,) if ticket else ()).fetchone()
    if not row:
        raise ValueError("No pending item for this selection")
    return row["ticket"], json.loads(row["card"])


def checked_answer(label, evidence, seconds, timing):
    if label not in LABELS or timing not in ("manual", "clock"):
        raise ValueError("Unknown label or timing mode")
    required_text(evidence, "evidence or uncertainty reason")
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("Active seconds must be finite and positive")
    return label, evidence.strip(), float(seconds), timing


def record(path, ticket, label, evidence, seconds, timing):
    answer = checked_answer(label, evidence, seconds, timing)
    with db(path, "rw") as conn:
        if sealed(conn):
            raise ValueError("Packet is sealed")
        next_card(conn, ticket)
        conn.execute("INSERT INTO answers VALUES (?,?,?,?,?)", (ticket, *answer))


def show(path, ticket=None):
    with db(path) as conn:
        if sealed(conn):
            raise ValueError("Packet is sealed")
        ticket, info = next_card(conn, ticket)
    print(json.dumps({"ticket": ticket, **info}, ensure_ascii=False, indent=2))
    return ticket


def session(args, clock=time.monotonic, read=input):
    ticket = show(args.packet, args.ticket)
    active, start = 0.0, clock()
    while True:
        command = read("p=pause, r=resume, a=answer, q=quit without saving > ").strip().lower()
        if command == "q":
            return
        if command == "p" and start is not None:
            active += clock() - start
            start = None
        elif command == "r" and start is None:
            start = clock()
        elif command == "a" and start is not None:
            label = read("/".join(LABELS) + " > ").strip()
            reason = read("Evidence or uncertainty reason > ").strip()
            elapsed = round(active + clock() - start, 3)
            record(args.packet, ticket, label, reason, elapsed, "clock")
            return
        else:
            print("Use r to resume before answering; q discards this attempt.")


def answer_digest(conn):
    rows = [tuple(r) for r in conn.execute("SELECT ticket,label,evidence,seconds,timing "
                                           "FROM answers ORDER BY ticket")]
    return digest(canonical(rows).encode())


def status(path):
    with db(path) as conn:
        assigned = conn.execute("SELECT count(*) FROM items").fetchone()[0]
        done = conn.execute("SELECT count(*) FROM answers").fetchone()[0]
        state = {"assigned": assigned, "completed": done, "pending": assigned - done, "sealed": sealed(conn)}
        if state["sealed"]:
            receipt = conn.execute("SELECT answers_sha256 FROM state").fetchone()[0]
            if receipt != answer_digest(conn):
                raise ValueError("Sealed answers were changed")
            state["answers_sha256"] = receipt
        print(canonical(state))


def seal(args):
    with db(args.packet, "rw") as conn:
        pending = conn.execute("SELECT count(*) FROM items LEFT JOIN answers USING(ticket) "
                               "WHERE answers.ticket IS NULL").fetchone()[0]
        if pending and not args.allow_pending:
            raise ValueError(f"{pending} pending. Use --allow-pending to close a partial review.")
        commitment = answer_digest(conn)
        if sealed(conn) and commitment != conn.execute("SELECT answers_sha256 FROM state").fetchone()[0]:
            raise ValueError("Sealed answers were changed")
        conn.execute("UPDATE state SET sealed=1,answers_sha256=?", (commitment,))
    print(f"Sealed. Pending: {pending}. Answer receipt SHA-256: {commitment}")


def load_batch(folder):
    root = Path(folder)
    manifest = json_file(root / "coordinator.json")
    if manifest["version"] != PACKET_VERSION:
        raise ValueError("Unknown batch version")
    answers, all_cards = {}, {}
    for role in ROLES:
        meta = manifest["roles"][role]
        with db(root / (role + ".sqlite")) as conn:
            if not sealed(conn):
                raise ValueError("Both independent packets must be sealed first")
            if conn.execute("SELECT answers_sha256 FROM state").fetchone()[0] != answer_digest(conn):
                raise ValueError(f"Packet {role} sealed answer commitment mismatch")
            items = [tuple(row) for row in conn.execute("SELECT pos,ticket,card FROM items ORDER BY pos")]
            committed = digest(canonical(items).encode())
            if committed != meta["cards_sha256"]:
                raise ValueError(f"Packet {role} card/order commitment mismatch")
            for _, ticket, text in items:
                all_cards[meta["tickets"][ticket]] = json.loads(text)
            answers[role] = {}
            for r in conn.execute("SELECT ticket,label,evidence,seconds,timing FROM answers"):
                checked_answer(r["label"], r["evidence"], r["seconds"], r["timing"])
                answers[role][meta["tickets"][r["ticket"]]] = dict(r)
    return manifest, all_cards, answers


def paired_cases(cards, answers):
    return [key for key in cards if all(key in answers[role] for role in ROLES)]


def agreement(matrix):
    n = sum(map(sum, matrix))
    if not n:
        return {"n_paired": 0, "agreement_pct": None, "kappa": None}
    diagonal = sum(row[i] for i, row in enumerate(matrix))
    expected_num = sum(sum(matrix[i]) * sum(row[i] for row in matrix) for i in range(len(matrix)))
    denominator = n*n - expected_num
    return {"n_paired": n, "agreement_pct": 100 * diagonal/n,
            "kappa": (diagonal*n - expected_num)/denominator if denominator else None}


def times(values):
    ordered = sorted(values)
    return {"n_timed": len(ordered), "active_minutes_total": sum(ordered)/60,
            "median_seconds": statistics.median(ordered) if ordered else None,
            "p90_seconds_nearest_rank": ordered[math.ceil(.90*len(ordered))-1] if ordered else None}


def needs_adjudication(key, answers):
    left, right = (answers[r][key]["label"] for r in ROLES)
    return left != right or left == "indeterminate"


def response_commitment(answers):
    return digest(canonical(answers).encode())


def read_adjudications(path, answers):
    if not path.exists():
        return {}
    with db(path) as conn:
        if conn.execute("SELECT base FROM metadata").fetchone()[0] != response_commitment(answers):
            raise ValueError("Adjudications belong to different independent responses")
        resolved = {}
        for row in conn.execute("SELECT * FROM decisions"):
            checked_answer(row["label"], row["evidence"], row["seconds"], "manual")
            if not all(row["id"] in answers[role] for role in ROLES) or not needs_adjudication(row["id"], answers):
                raise ValueError("Unexpected adjudication ID")
            resolved[row["id"]] = dict(row)
        return resolved


def report(folder):
    manifest, cards, answers = load_batch(folder)
    pairs = paired_cases(cards, answers)
    matrix = [[0 for _ in LABELS] for _ in LABELS]
    for key in pairs:
        left, right = (LABELS.index(answers[r][key]["label"]) for r in ROLES)
        matrix[left][right] += 1
    queue = {k for k in pairs if needs_adjudication(k, answers)}
    decisions = read_adjudications(Path(folder) / "adjudication.sqlite", answers)
    report_by_role = {}
    for role in ROLES:
        rows = list(answers[role].values())
        report_by_role[role] = {"assigned": len(cards), "completed": len(rows),
                                "pending": len(cards)-len(rows),
                                "label_counts": {l: sum(r["label"]==l for r in rows) for l in LABELS},
                                "clock": sum(r["timing"]=="clock" for r in rows),
                                "manual": sum(r["timing"]=="manual" for r in rows),
                                **times([r["seconds"] for r in rows])}
    final = {l: 0 for l in LABELS}
    for key in pairs:
        if key not in queue:
            final[answers["A"][key]["label"]] += 1
        elif key in decisions:
            final[decisions[key]["label"]] += 1
    return {"mode": manifest["mode"], "n_cases": len(cards), "assigned_review_tasks": 2*len(cards),
            "pending_review_tasks": sum(r["pending"] for r in report_by_role.values()),
            "observed_person_minutes_including_adjudication": sum(r["active_minutes_total"] for r in report_by_role.values())
                + sum(r["seconds"] for r in decisions.values()) / 60,
            "reviewers": report_by_role, "matrix_labels_A_rows_B_columns": list(LABELS),
            "matrix": matrix, **agreement(matrix), "pending_pairs": len(cards)-len(pairs),
            "double_review_active_time": times([sum(answers[r][k]["seconds"] for r in ROLES) for k in pairs]),
            "adjudication": {"required": len(queue), "completed": len(decisions), "pending": len(queue)-len(decisions),
                             **times([r["seconds"] for r in decisions.values()])},
            "final_case_counts": final, "cases_without_final_disposition": len(cards)-sum(final.values())}


def adjudicate(args):
    path = Path(args.batch) / "adjudication.sqlite"
    _, cards, answers = load_batch(args.batch)
    prior = read_adjudications(path, answers)
    queue = [k for k in paired_cases(cards, answers) if needs_adjudication(k, answers) and k not in prior]
    if args.case is None:
        if any(x is not None for x in (args.label, args.evidence, args.seconds)):
            raise ValueError("Use --case with all decision fields")
        if not queue:
            print("No paired cases pending adjudication.")
            return
        key = queue[0]
        print(json.dumps({"id": key, "card": cards[key],
                          "independent": {r: {x: answers[r][key][x] for x in ("label","evidence")} for r in ROLES}},
                         ensure_ascii=False, indent=2))
        return
    if args.case not in queue:
        raise ValueError("Case is not awaiting adjudication")
    label, evidence, seconds, _ = checked_answer(args.label, args.evidence, args.seconds, "manual")
    commitment = response_commitment(answers)
    with db(path, "rwc") as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS metadata (base TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY,label TEXT,evidence TEXT,seconds REAL)")
        row = conn.execute("SELECT base FROM metadata").fetchone()
        if row is None:
            conn.execute("INSERT INTO metadata VALUES (?)", (commitment,))
        elif row[0] != commitment:
            raise ValueError("Independent response commitment mismatch")
        conn.execute("INSERT INTO decisions VALUES (?,?,?,?)", (args.case, label, evidence, seconds))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("prepare")
    for name in ("cases", "events", "freeze", "freeze-sha256", "out"):
        p.add_argument("--"+name, required=True)
    p.add_argument("--mode", choices=("simulation","human_collection"), required=True)
    p.set_defaults(run=prepare)
    for name in ("show", "session", "record", "seal", "status"):
        p = subs.add_parser(name)
        p.add_argument("packet")
        if name in ("show","session","record"):
            p.add_argument("--ticket", required=name=="record")
        if name == "status":
            p.set_defaults(run=lambda a: status(a.packet))
        if name == "show":
            p.set_defaults(run=lambda a: show(a.packet, a.ticket))
        if name == "session":
            p.set_defaults(run=session)
        if name == "record":
            p.add_argument("--label", choices=LABELS, required=True)
            p.add_argument("--evidence", required=True)
            p.add_argument("--seconds", type=float, required=True)
            p.set_defaults(run=lambda a: record(a.packet,a.ticket,a.label,a.evidence,a.seconds,"manual"))
        if name == "seal":
            p.add_argument("--allow-pending",action="store_true")
            p.set_defaults(run=seal)
    p = subs.add_parser("report")
    p.add_argument("batch")
    p.set_defaults(run=lambda a: print(json.dumps(report(a.batch), ensure_ascii=False, indent=2, allow_nan=False)))
    p = subs.add_parser("adjudicate")
    p.add_argument("batch")
    p.add_argument("--case")
    p.add_argument("--label", choices=LABELS)
    p.add_argument("--evidence")
    p.add_argument("--seconds", type=float)
    p.set_defaults(run=adjudicate)
    args = parser.parse_args(argv)
    try:
        args.run(args)
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, EOFError) as e:
        parser.exit(2, f"review: {e}\n")


if __name__ == "__main__":
    main()
