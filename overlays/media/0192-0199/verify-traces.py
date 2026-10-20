"""Portable behavioral traces against memory and SQLite fixture adapters.

The SQLite adapter is actually killed before/after COMMIT and reopened. These
small adapters establish the specified schedules, not a production HTTP service,
wallet implementation, browser store, or deployment's isolation guarantees.
"""

import copy, gzip, json, os, sqlite3, subprocess, sys, tempfile
from pathlib import Path
from bitcoinx import Tx

HERE = Path(__file__).parent


def write_cells(path, state, crash=None):
    db = sqlite3.connect(path)
    db.execute("BEGIN IMMEDIATE")
    db.execute("DELETE FROM cells")
    for key, value in state.items():
        db.execute(
            "INSERT INTO cells VALUES (?,?)",
            (key, json.dumps(value, separators=(",", ":"))),
        )
    if crash == "crash-before-commit":
        os._exit(73)
    db.commit()
    if crash == "crash-after-commit":
        os._exit(73)
    db.close()


if len(sys.argv) > 1 and sys.argv[1] == "worker":
    write_cells(sys.argv[2], json.loads(sys.stdin.read()), sys.argv[3])
    sys.exit()
wire = json.loads(gzip.decompress((HERE / "wire-vectors.json.gz").read_bytes()))
vectors = json.loads((HERE / "trace-vectors.json").read_text())
old = (
    wire["publications"]["request"]
    if "publications" in wire
    else wire["publication"]["request"]
)
first = wire["acquisitions"][0]
old_tx = Tx.from_hex(wire["transactions"][old["evidence"]["txid"]]["raw"])
new_tx = Tx.from_hex(wire["transactions"][first["submit"]["txid"]]["raw"])


class Memory:
    def __init__(self, path):
        self.state = {}

    def read(self):
        return copy.deepcopy(self.state)

    def write(self, state, crash=None):
        if crash != "crash-before-commit":
            self.state = copy.deepcopy(state)

    def restart(self):
        pass


class SQLite:
    def __init__(self, path):
        self.path = path
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE cells(key TEXT PRIMARY KEY,value TEXT NOT NULL)")

    def read(self):
        with sqlite3.connect(self.path) as db:
            return {
                k: json.loads(v) for k, v in db.execute("SELECT key,value FROM cells")
            }

    def write(self, state, crash=None):
        if crash:
            p = subprocess.run(
                [sys.executable, __file__, "worker", str(self.path), crash],
                input=json.dumps(state),
                text=True,
            )
            assert p.returncode == 73
        else:
            write_cells(self.path, state)

    def restart(self):
        self.read()  # Fresh connections are already used per operation.


def initial(kind):
    if kind == "knowledge":
        return dict(
            received=0,
            accepted=0,
            projected=0,
            members=["old"],
            pending=False,
            stale=False,
            reset=False,
            context="view-0",
            walletEffects=0,
            receivedGroup=False,
            verified=[],
            acceptedMembers=["old"],
            jobContext="view-0",
        )
    if kind == "session":
        return dict(
            state="absent",
            snapshot=None,
            expires=None,
            replayUntil=None,
            last=None,
            opens=0,
            walletEffects=0,
        )
    if kind == "proposal":
        return dict(
            status="absent",
            headRevision=0,
            admissions=0,
            last=None,
            events=[],
            walletEffects=0,
        )
    if kind == "acquisition":
        return dict(
            status="absent",
            pinned=False,
            walletEffects=0,
            internalizeCalls=0,
            reconcileCalls=0,
            last=None,
            recoverUntil=173400,
        )
    if kind == "root":
        return dict(
            revision=0,
            blockers=[],
            served=False,
            continuity="intact",
            actions=[],
            walletEffects=0,
        )
    raise AssertionError(kind)


def apply(kind, s, event):
    name = event[0]
    arg = event[1] if len(event) > 1 and isinstance(event[1], int) else None
    if kind == "knowledge":
        if name == "receive" and not s["receivedGroup"]:
            batch = wire["live"]["live"]
            assert all(
                o["scope"] == batch["scope"]
                for g in batch["groups"]
                for o in g["observations"]
            )
            s.update(
                received=s["received"] + 1, pending=True, stale=True, receivedGroup=True
            )
        elif name == "verify-spend":
            assert (
                new_tx.inputs[0].prev_hash == old_tx.hash()
                and new_tx.inputs[0].prev_idx == 0
            )
            s["verified"] = sorted(set(s["verified"] + ["spend"]))
        elif name == "verify-output":
            assert new_tx.outputs[0].value == old_tx.outputs[0].value + 1001
            assert new_tx.outputs[0].script_pubkey == old_tx.outputs[0].script_pubkey
            s["verified"] = sorted(set(s["verified"] + ["output"]))
        elif name == "invalid-output-index":
            assert len(new_tx.outputs) < 999
            s["reset"] = True
        elif name == "context-change":
            s.update(
                context="view-1",
                received=s["received"] + 1,
                accepted=s["accepted"] + 1,
                stale=True,
            )
        elif (
            name == "accept"
            and s["pending"]
            and not s["reset"]
            and s["context"] == s["jobContext"]
            and s["verified"] == ["output", "spend"]
        ):
            s.update(
                received=s["received"] + 1,
                accepted=s["accepted"] + 1,
                pending=False,
                acceptedMembers=["new"],
            )
        elif name == "project":
            s["projected"] = s["accepted"]
            s["members"] = s["acceptedMembers"]
            s["stale"] = s["pending"] or s["reset"]
    elif kind == "session":
        if name == "open":
            if s["state"] == "absent":
                s.update(
                    state="open",
                    snapshot="W10",
                    expires=arg + 300,
                    replayUntil=arg + 900,
                    opens=1,
                    last="opened",
                )
            elif s["state"] == "open" and arg < s["expires"]:
                s["last"] = "replayed"
            else:
                s["last"] = "expired"
        elif name == "close":
            s.update(state="closed", last="closed")
        elif name == "revoke":
            s.update(state="revoked", last="unauthorized")
        elif name in ["serialize", "read"]:
            if s["state"] == "revoked":
                s["last"] = "unauthorized"
            elif s["state"] == "closed":
                s["last"] = "expired"
            elif arg >= s["expires"]:
                s.update(state="expired", last="reset-required")
            else:
                s["last"] = "resume"
    elif kind == "proposal":
        if name == "put":
            if s["status"] == "absent":
                s.update(status="active", last="recorded")
                s["events"].append("active")
            else:
                s["last"] = "conflict"
        elif name == "finalize":
            if s["status"] == "active":
                final = wire["proposalFinalization"]
                tx = Tx.from_hex(wire["transactions"][final["txid"]]["raw"])
                assert tx.outputs[0].script_pubkey.to_bytes() == bytes.fromhex(
                    "006a24"
                ) + b"PRP1" + bytes.fromhex(final["proposalId"])
                s.update(status="finalizing", last="pending")
                s["events"].append("finalizing")
            elif s["status"] == "finalized":
                s["last"] = "replayed"
            else:
                s["last"] = "pending" if s["status"] == "finalizing" else "conflict"
        elif name == "admit":
            assert s["status"] == "finalizing"
            s["admissions"] = 1
        elif (
            name == "reconcile" and s["admissions"] == 1 and s["status"] == "finalizing"
        ):
            s.update(status="finalized", last="finalized")
            s["events"].append("finalized")
        elif name == "expire" and s["status"] == "active":
            s.update(status="expired", last="expired")
            s["events"].append("expired")
        elif name == "update":
            s["last"] = "conflict" if s["status"] != "active" else "recorded"
        elif name == "compact":
            pass  # Permanent terminal fence is retained.
    elif kind == "acquisition":
        if name == "quote":
            s.update(status="quoted", last="quoted")
        elif name == "receive-payment":
            if arg >= s["recoverUntil"] and not s["pinned"]:
                s.update(status="expired", last="expired")
            else:
                paid = wire["acquisitions"][2]
                tx = Tx.from_hex(
                    wire["transactions"][paid["result"]["funding"]["txid"]]["raw"]
                )
                matches = [
                    o
                    for o in tx.outputs
                    if o.script_pubkey.to_hex() == paid["expectedPaymentScript"]
                ]
                assert len(matches) == 1 and matches[0].value == 1001
                s.update(status="funding-pending", pinned=True, last="pending")
        elif name == "wallet-accept":
            assert s["pinned"]
            s["internalizeCalls"] += 1
            s["walletEffects"] = 1
        elif name == "reconcile":
            s["reconcileCalls"] += 1
            if s["walletEffects"] == 1:
                s.update(status="delivery-pending", last="delivery-pending")
        elif name == "deliver":
            assert s["walletEffects"] == 1
            s.update(
                status="delivered",
                last="delivered",
                recoverUntil=max(s["recoverUntil"], arg + 86400),
            )
        elif name == "recover":
            s["last"] = s["status"]
        elif name == "wrong-recipient":
            s["last"] = "not-found"
    elif kind == "root":
        if name.startswith(("suppress-", "restore-")):
            trace = next(x for x in wire["rootTrace"] if x["name"] == name)
            if name not in s["actions"]:
                s["actions"].append(name)
                s["revision"] += 1
                if name.startswith("suppress-"):
                    s["blockers"].append(name[-1])
                else:
                    s["blockers"].remove(name[-1])
                assert trace["result"]["body"]["outcomes"][0]["revision"] == str(
                    s["revision"]
                )
        elif name in ["serve-cache", "serve-snapshot", "serve-live", "gasp-reindex"]:
            s["served"] = not s["blockers"]
            if s["blockers"] and name in ["serve-snapshot", "serve-live"]:
                s["continuity"] = "reset-required"
    return s


def view(kind, state):
    hidden = (
        ["receivedGroup", "verified", "acceptedMembers", "jobContext"]
        if kind == "knowledge"
        else []
    )
    return {k: v for k, v in state.items() if k not in hidden}


runs = crashes = 0
with tempfile.TemporaryDirectory(prefix="brc-traces-") as tmp:
    for index, case in enumerate(vectors["cases"]):
        for adapter in [Memory, SQLite]:
            store = adapter(Path(tmp) / f"{index}.sqlite")
            store.write(initial(case["kind"]))
            for event in case["commands"]:
                if event[0] == "restart":
                    store.restart()
                    continue
                crash = next(
                    (x for x in event if isinstance(x, str) and x.startswith("crash-")),
                    None,
                )
                store.write(apply(case["kind"], store.read(), event), crash)
                if crash and adapter is SQLite:
                    crashes += 1
            actual = view(case["kind"], store.read())
            assert actual == case["expected"], (
                case["name"],
                adapter.__name__,
                actual,
                case["expected"],
            )
            runs += 1
print(
    json.dumps(
        {
            "behavioralScenarios": len(vectors["cases"]),
            "adapterRuns": runs,
            "sqliteProcessCrashes": crashes,
            "adapters": ["memory", "SQLite WAL"],
            "scope": "offline fixture adapters; production lifecycle qualification remains separate",
        }
    )
)
