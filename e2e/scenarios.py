# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""The scenarios. Each one gets its own new database and a freshly unpacked engine; the SSH server and the
listener behind the remote forwards are shared by the whole run (ctx).

A check that fails is a FAIL and fails the run. A NOTE records something without judging it.
"""

import hashlib
import os
import re
import zipfile

import tunnels as t
from engine import free_port
from oie import Api
from sshd import PASSWORD, fingerprint
from traffic import port_open, read_line, wait_closed


class Report:
    def __init__(self, scenario):
        self.scenario = scenario
        self.passed = 0
        self.failed = []
        self.notes = []

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
        else:
            self.failed.append(name)
        print(f"{'PASS' if ok else 'FAIL'} [{self.scenario}] {name}" + (f"  [{detail}]" if detail and not ok else ""),
              flush=True)
        return ok

    def note(self, name, value):
        self.notes.append(f"{name}: {value}")
        print(f"NOTE [{self.scenario}] {name}: {value}", flush=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_server_jar(r, engine, zip_path):
    """The installed server jar must be the zip's, and the only one (an upgrade must not leave the old one)."""
    with zipfile.ZipFile(zip_path) as z:
        name = next(n for n in z.namelist() if re.search(r"oie-ssh-tunnel-manager-server-[^/]*\.jar$", n))
        want = sha256(z.read(name))
    files = engine.extension_files(t.PLUGIN_PATH) or []
    jars = [f for f in files if f.startswith("oie-ssh-tunnel-manager-server-")]
    got = None
    if len(jars) == 1:
        with open(os.path.join(engine.home, "extensions", t.PLUGIN_PATH, jars[0]), "rb") as f:
            got = sha256(f.read())
    r.check(f"installed server jar is {os.path.basename(name)} and the only one",
            jars == [os.path.basename(name)] and got == want, f"found {jars}")


def install_and_restart(r, engine, api, zip_path):
    ok, detail = t.install(api, zip_path)
    r.check(f"install {os.path.basename(zip_path)}", ok, detail)
    api = engine.restart()
    check_server_jar(r, engine, zip_path)
    return api


def check_logs(r, engine, allowed=(), where=""):
    """allowed: regular expressions for ERROR and WARN lines this scenario causes on purpose."""
    for level in ("ERROR", "WARN"):
        lines = [line for line in engine.plugin_log_lines(level) if not any(re.search(p, line) for p in allowed)]
        r.check(f"no unexpected {level} lines from the plugin in mirth.log{where}", not lines, " | ".join(lines[:3]))


def host_key(api, ctx):
    hk = t.fetch_host_key(api, ctx.sshd.port)
    return hk["keyType"], hk["publicKey"]


def check_traffic(r, ctx, lport, rport, where):
    banner = read_line(lport)
    r.check(f"{where}the local forward reaches the SSH server's port 22 (its banner)",
            bool(banner) and banner.startswith("SSH-2.0-"), repr(banner))
    got = ctx.sshd.read_from(rport)
    r.check(f"{where}the remote forward reaches the listener on the engine's machine", got == ctx.listener.marker,
            repr(got))


def make_pair(r, api, ctx, key, prefix, where=""):
    """A password tunnel with a local forward and a key tunnel with a remote forward, both connected."""
    lport, rport = free_port(), ctx.sshd.next_port()
    pid = t.create(api, t.tunnel(f"{prefix} password", ctx.sshd.port, key, password=PASSWORD,
                                 forwards=[t.local(lport, 22)]))
    kid = t.create(api, t.tunnel(f"{prefix} key", ctx.sshd.port, key, key=ctx.private_key,
                                 passphrase=ctx.passphrase, forwards=[t.remote(rport, ctx.listener.port)]))
    for tid, label in ((pid, "password"), (kid, "pasted key")):
        status = t.wait_state(api, tid, "CONNECTED")
        r.check(f"{where}the {label} tunnel connects", status["state"] == "CONNECTED", str(status))
    check_traffic(r, ctx, lport, rport, where)
    return pid, kid, lport, rport


def wait_connected(r, api, ids, where):
    for tid, label in ids:
        status = t.wait_state(api, tid, "CONNECTED")
        r.check(f"{where}the {label} tunnel is connected", status["state"] == "CONNECTED", str(status))


# ---------- fresh install: every feature

HOSTKEY_CONTROL = "e2e host key control"


def fresh(r, engine, db, dbname, new_zip, ctx, **_):
    api = engine.start()
    api = install_and_restart(r, engine, api, new_zip)

    hk = t.fetch_host_key(api, ctx.sshd.port)
    r.check("fetch host key: it is the server's own key of that type",
            ctx.sshd.host_keys().get(hk["keyType"]) == hk["publicKey"], hk["keyType"])
    r.check("fetch host key: the fingerprint is the key's SHA256", hk["fingerprint"] == fingerprint(hk["publicKey"]),
            hk["fingerprint"])
    key = (hk["keyType"], hk["publicKey"])
    pid, kid, lport, rport = make_pair(r, api, ctx, key, "e2e")
    names = {pid: "e2e password", kid: "e2e key"}

    listed = t.tunnels(api)
    r.check("the list masks the password", listed[pid]["password"] == t.MASK, listed[pid]["password"])
    r.check("the list masks the private key and its passphrase",
            listed[kid]["privateKeyPem"] == t.MASK and listed[kid]["privateKeyPassphrase"] == t.MASK)
    check_at_rest(r, db, dbname, ctx)
    derived = t.derive_public_key(api, listed[kid])
    r.check("derive the public key from the stored key: it is the client's",
            derived.split()[:2] == ctx.public_key.split()[:2], derived[:80])
    r.check("reveal the stored private key", t.reveal_key(api, kid).strip() == ctx.private_key.strip())

    ok, steps = t.test_connection(api, listed[pid])
    r.check("the diagnostic passes for the password tunnel", ok, str(steps))
    ok, steps = t.test_connection(api, t.tunnel("e2e wrong password", ctx.sshd.port, key, password="not-it"))
    r.check("control: the diagnostic fails at Authentication for a wrong password",
            not ok and steps.get("Authentication", ("",))[0] == "FAIL", str(steps))

    wrong = ("ssh-ed25519", ctx.public_key.split()[1])   # a real key, but not the server's
    xid = t.create(api, t.tunnel(HOSTKEY_CONTROL, ctx.sshd.port, wrong, password=PASSWORD))
    status = t.wait_state(api, xid, "FAILED")
    r.check("control: a wrong pinned host key fails the tunnel",
            status["state"] == "FAILED" and "Host key verification failed" in status["lastError"], str(status))
    r.check("the failed tunnel raised a Tunnel Down event", any(
        e.get("Action") == "Tunnel Down" and e.get("Tunnel") == HOSTKEY_CONTROL for e in t.plugin_events(api)))
    t.delete(api, xid)

    t.stop(api, pid)
    status = t.wait_state(api, pid, "DISCONNECTED")
    r.check("stop: the password tunnel disconnects", status["state"] == "DISCONNECTED", str(status))
    r.check("stop: its local port closes", wait_closed(lport))
    t.start(api, pid)
    wait_connected(r, api, [(pid, "password")], "start: ")
    banner = read_line(lport)
    r.check("start: the local forward carries traffic again", bool(banner) and banner.startswith("SSH-2.0-"))

    r.check("the SSH server ends every session", ctx.sshd.drop_sessions())
    for tid, label in ((pid, "password"), (kid, "pasted key")):
        r.check(f"the {label} tunnel records the lost connection", t.wait_event(api, tid, "Connection lost"))
    wait_connected(r, api, [(pid, "password"), (kid, "pasted key")], "after the server drops them: ")
    check_traffic(r, ctx, lport, rport, "after the reconnect: ")

    api = engine.restart()
    r.check("after an engine restart: both tunnels are still listed", set(t.tunnels(api)) == {pid, kid})
    wait_connected(r, api, [(pid, "password"), (kid, "pasted key")], "after an engine restart: ")
    check_traffic(r, ctx, lport, rport, "after an engine restart: ")
    r.check("the tunnel's history records the connect",
            any((m or "").startswith("Connected to tunnel@127.0.0.1") for _, m in t.events(api, pid)))

    seen = {(e.get("Action"), e.get("Tunnel")) for e in t.plugin_events(api, limit=500)}
    for action, name in (("Created", names[pid]), ("Created", names[kid]), ("Stopped", names[pid]),
                         ("Started", names[pid]), ("Deleted", HOSTKEY_CONTROL)):
        r.check(f"the engine's event log has '{action}' for {name}", (action, name) in seen)

    t.delete(api, pid)
    r.check("delete: the tunnel is gone from the list", pid not in t.tunnels(api))
    r.check("delete: its local port closes", wait_closed(lport))
    check_logs(r, engine, allowed=(
        rf"Tunnel '{HOSTKEY_CONTROL}' connection attempt \d+ failed: Host key verification failed",
        r"Tunnel 'e2e (password|key)' lost its connection"))


def check_at_rest(r, db, dbname, ctx):
    if db.config_rows(dbname) is None:
        r.note("secrets at rest", "not read for Derby (embedded in the engine); the API checks still run")
        return
    r.check("the tunnels are stored in the engine's CONFIGURATION table", db.config_rows(dbname) >= 1)
    r.check("control: the stored secrets carry the {enc} marker", db.config_rows(dbname, "{enc}") >= 1)
    for label, text in (("password", PASSWORD), ("key passphrase", ctx.passphrase), ("private key", ctx.key_marker)):
        r.check(f"the {label} is not stored in plain text", db.config_rows(dbname, text) == 0)


# ---------- upgrade from a published release

def upgrade(r, engine, db, dbname, new_zip, old_zip, ctx, upgrade_engine=None, **_):
    """With upgrade_engine, the old release runs on the older engine it was built for, and the engine is upgraded
    under it before the new zip goes in: the path every user of the old release takes."""
    api = engine.start()
    api = install_and_restart(r, engine, api, old_zip)
    key = host_key(api, ctx)
    pid, kid, lport, rport = make_pair(r, api, ctx, key, "e2e upgrade", "old version: ")

    engines, skipped = [engine], []
    if upgrade_engine:
        engine.stop()
        engine = upgrade_engine(engine)
        engines.append(engine)
        api = engine.start()
        # Control: the old release is still installed under the upgraded engine, which skips it.
        skipped = [line for line in engine.plugin_log_lines("ERROR") if "is not compatible" in line]
        r.check("after the engine upgrade: the engine skipped the old release", len(skipped) == 1,
                f"{len(skipped)} 'is not compatible' lines")

    api = install_and_restart(r, engine, api, new_zip)
    r.check("after the upgrade: both tunnels are listed", set(t.tunnels(api)) == {pid, kid}, str(list(t.tunnels(api))))
    wait_connected(r, api, [(pid, "password"), (kid, "pasted key")], "after the upgrade: ")
    check_traffic(r, ctx, lport, rport, "after the upgrade: ")
    r.check("after the upgrade: the stored private key reads back",
            t.reveal_key(api, kid).strip() == ctx.private_key.strip())
    # The plugin refuses to save over a stored list it couldn't read, so a save shows the old list loaded.
    nid = t.create(api, t.tunnel("e2e upgrade new", ctx.sshd.port, key, password=PASSWORD, enabled=False))
    r.check("after the upgrade: a new tunnel saves", nid in t.tunnels(api))
    if upgrade_engine:
        check_logs(r, engines[0], where=" (old engine)")
    check_logs(r, engine, allowed=tuple(re.escape(line) for line in skipped))


# ---------- uninstall and reinstall

def uninstall(r, engine, db, dbname, new_zip, ctx, **_):
    api = engine.start()
    api = install_and_restart(r, engine, api, new_zip)
    key = host_key(api, ctx)
    lport = free_port()
    uid = t.create(api, t.tunnel("e2e uninstall", ctx.sshd.port, key, password=PASSWORD,
                                 forwards=[t.local(lport, 22)]))
    wait_connected(r, api, [(uid, "password")], "before the uninstall: ")
    banner = read_line(lport)
    r.check("the tunnel's local forward works before the uninstall", bool(banner) and banner.startswith("SSH-2.0-"))
    rows = db.config_rows(dbname)
    if rows is None:
        r.note("CONFIGURATION rows", "not read for Derby (embedded in the engine); the API checks still run")
    else:
        r.check("the plugin's CONFIGURATION rows exist before the uninstall", rows >= 1, f"found {rows}")
    # Control for the 'gone' checks below: the same calls must see the plugin while it is installed.
    r.check("the plugin is listed before the uninstall", t.plugin_installed(api))
    r.check("its extension folder exists before the uninstall", engine.extension_files(t.PLUGIN_PATH) is not None)

    ok, detail = t.uninstall(api)
    r.check("uninstall the plugin", ok, detail)
    api = engine.restart()
    r.check("the plugin is gone after the restart", not t.plugin_installed(api))
    r.check("its extension folder is gone", engine.extension_files(t.PLUGIN_PATH) is None)
    r.check("its local forward is closed", wait_closed(lport))
    rows = db.config_rows(dbname)
    if rows is not None:
        r.check("uninstall removed the plugin's CONFIGURATION rows", rows == 0, f"{rows} left")

    api = install_and_restart(r, engine, api, new_zip)
    r.check("after reinstall: no tunnels", t.tunnels(api) == {})
    r.check("after reinstall: the old local port stays closed", not port_open(lport))
    lport = free_port()
    nid = t.create(api, t.tunnel("e2e reinstall", ctx.sshd.port, key, password=PASSWORD, forwards=[t.local(lport, 22)]))
    wait_connected(r, api, [(nid, "new")], "after reinstall: ")
    banner = read_line(lport)
    r.check("after reinstall: a new tunnel carries traffic", bool(banner) and banner.startswith("SSH-2.0-"))
    check_logs(r, engine)


# ---------- rbac installed alongside

VIEW, MANAGE = "viewSshTunnels", "manageSshTunnels"


def operations(ctx, key, stored, spare, user):
    """Every endpoint the plugin has: (operation, permission it needs, method, path, body, query). stored is the
    admin's tunnel as listed (secrets masked), so updating it with itself changes nothing."""
    pid = stored["id"]
    keyed = t.tunnel("e2e rbac derive", ctx.sshd.port, key, key=ctx.private_key, passphrase=ctx.passphrase)
    new = t.tunnel(f"e2e rbac by {user}", ctx.sshd.port, key, password=PASSWORD, enabled=False)
    return [
        ("getTunnels", VIEW, "GET", "/tunnels", None, None),
        ("getStatuses", VIEW, "GET", "/statuses", None, None),
        ("getTunnelEvents", VIEW, "GET", f"/tunnels/{pid}/events", None, None),
        ("createTunnel", MANAGE, "POST", "/tunnels", t.to_xml(new), None),
        ("updateTunnel", MANAGE, "PUT", f"/tunnels/{pid}", t.to_xml(stored), None),
        ("startTunnel", MANAGE, "POST", f"/tunnels/{pid}/_start", None, None),
        ("stopTunnel", MANAGE, "POST", f"/tunnels/{spare}/_stop", None, None),
        ("deleteTunnel", MANAGE, "DELETE", f"/tunnels/{spare}", None, None),
        ("testConnection", MANAGE, "POST", "/_testConnection", t.to_xml(stored), None),
        ("fetchHostKey", MANAGE, "POST", "/_fetchHostKey", None, {"host": "127.0.0.1", "port": ctx.sshd.port}),
        ("derivePublicKey", MANAGE, "POST", "/_derivePublicKey", t.to_xml(keyed), None),
        ("revealPrivateKey", MANAGE, "POST", f"/tunnels/{pid}/_revealKey", None, None),
    ]


def rbac(r, engine, db, dbname, new_zip, rbac_zip, ctx, **_):
    """rbac installed alongside. Each of the plugin's 12 endpoints must need the permission it declares: a
    view-only role reads and is refused every change, a role without the tunnel permissions (limited to some
    channels) is refused everything, and a manage role and admin, the control, can do everything."""
    api = engine.start()
    for z in (new_zip, rbac_zip):
        ok, detail = t.install(api, z)
        r.check(f"install {os.path.basename(z)}", ok, detail)
    api = engine.restart()
    check_server_jar(r, engine, new_zip)
    r.check("rbac is running", t.rbac_answers(api))

    key = host_key(api, ctx)
    lport = free_port()
    pid = t.create(api, t.tunnel("e2e rbac", ctx.sshd.port, key, password=PASSWORD, forwards=[t.local(lport, 22)]))
    wait_connected(r, api, [(pid, "admin's")], "")

    roles = {
        "ssh-e2e-viewer": t.create_role(api, "SSH e2e view tunnels", [VIEW]),
        "ssh-e2e-manager": t.create_role(api, "SSH e2e manage tunnels", [VIEW, MANAGE]),
        "ssh-e2e-channels": t.create_role(api, "SSH e2e one channel, no tunnels", ["viewChannels"], [t.new_id()]),
    }
    granted = {"ssh-e2e-viewer": {VIEW}, "ssh-e2e-manager": {VIEW, MANAGE}, "ssh-e2e-channels": set(),
               "admin": {VIEW, MANAGE}}
    password = "Ssh-e2e-" + t.new_id()[:12] + "!"
    users = {"admin": api}
    for name, role in roles.items():
        user_id = t.create_user(api, name, password)
        t.assign_role(api, user_id, role)
        users[name] = Api(engine.port, name, password)
        users[name].login(wait=60)

    stored = t.tunnels(api)[pid]
    for name, user in users.items():
        spare = t.create(api, t.tunnel(f"e2e rbac spare for {name}", ctx.sshd.port, key, password=PASSWORD,
                                       enabled=False))
        for op, needs, method, path, body, query in operations(ctx, key, stored, spare, name):
            status, text = user.request(method, t.EXT + path, body, query=query)
            if needs in granted[name]:
                r.check(f"{name}: {op} is allowed", status in (200, 204), f"HTTP {status}: {text[:150]}")
            else:
                r.check(f"{name}: {op} is refused", status == 403, f"HTTP {status}: {text[:150]}")

    unmapped = [line for line in engine.log().splitlines()
                if "allowing unknown operation" in line and "SSH Tunnel Manager#" in line]
    r.check("rbac has a permission for every one of the plugin's operations", not unmapped, " | ".join(unmapped[:3]))
    r.check("the admin's tunnel is still there, unchanged", t.tunnels(api).get(pid) == stored)
    wait_connected(r, api, [(pid, "admin's")], "at the end: ")
    banner = read_line(lport)
    r.check("at the end: the admin's tunnel still carries traffic", bool(banner) and banner.startswith("SSH-2.0-"))
    check_logs(r, engine)
