# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""The plugin's REST API, plus the engine calls the scenarios need: extensions, users and rbac roles.

Tunnels go over the wire as the engine's XStream XML, with each class named in full."""

import os
import time
import uuid
import xml.etree.ElementTree as ET

from oie import ApiError

EXT = "/extensions/oie-ssh-tunnel-manager"
PLUGIN_PATH = "oie-ssh-tunnel-manager"
PKG = "com.diridium.oie.sshtunnel."
MASK = "********"
FIELDS = ("id", "name", "enabled", "host", "port", "username", "authMethod", "password", "keySource",
          "privateKeyPath", "privateKeyPem", "privateKeyPassphrase", "verifyHostKey", "acceptedHostKey",
          "acceptedHostKeyType", "serverAliveIntervalSeconds", "serverAliveCountMax")
FORWARD_FIELDS = ("direction", "bindHost", "bindPort", "destinationHost", "destinationPort")


def new_id():
    return str(uuid.uuid4())


# ---------- tunnels as dicts, and their XML

def local(bind_port, destination_port, destination_host="127.0.0.1"):
    """A local forward: 127.0.0.1:bind_port on the engine's machine to destination, as the SSH server sees it."""
    return {"direction": "LOCAL", "bindHost": "127.0.0.1", "bindPort": bind_port,
            "destinationHost": destination_host, "destinationPort": destination_port}


def remote(bind_port, destination_port, destination_host="127.0.0.1"):
    """A remote forward: 127.0.0.1:bind_port on the SSH server to destination, as the engine's machine sees it."""
    return {"direction": "REMOTE", "bindHost": "127.0.0.1", "bindPort": bind_port,
            "destinationHost": destination_host, "destinationPort": destination_port}


def tunnel(name, port, host_key, password=None, key=None, passphrase="", forwards=(), enabled=True):
    """A tunnel to the test SSH server on 127.0.0.1:port, pinned to host_key ((type, base64)). Password auth,
    or a pasted private key when key is given."""
    return {"name": name, "enabled": enabled, "host": "127.0.0.1", "port": port, "username": "tunnel",
            "authMethod": "PRIVATE_KEY" if key else "PASSWORD", "password": password or "",
            "keySource": "INLINE", "privateKeyPath": "", "privateKeyPem": key or "",
            "privateKeyPassphrase": passphrase, "verifyHostKey": True, "acceptedHostKey": host_key[1],
            "acceptedHostKeyType": host_key[0], "serverAliveIntervalSeconds": 30, "serverAliveCountMax": 3,
            "forwards": list(forwards)}


def to_xml(t):
    root = ET.Element(PKG + "SshTunnel")
    for field in FIELDS:
        if t.get(field) is not None:
            value = t[field]
            ET.SubElement(root, field).text = str(value).lower() if isinstance(value, bool) else str(value)
    holder = ET.SubElement(root, "forwards")
    for f in t.get("forwards", []):
        el = ET.SubElement(holder, PKG + "PortForward")
        for field in FORWARD_FIELDS:
            ET.SubElement(el, field).text = str(f[field])
    return ET.tostring(root, encoding="unicode")


def from_xml(el):
    t = {field: el.findtext(field) for field in FIELDS}
    for field in ("port", "serverAliveIntervalSeconds", "serverAliveCountMax"):
        t[field] = int(t[field]) if t[field] else 0
    t["enabled"] = t["enabled"] == "true"
    t["verifyHostKey"] = t["verifyHostKey"] == "true"
    t["forwards"] = [{field: f.findtext(field) for field in FORWARD_FIELDS} for f in el.iter(PKG + "PortForward")]
    for f in t["forwards"]:
        f["bindPort"], f["destinationPort"] = int(f["bindPort"]), int(f["destinationPort"])
    return t


# ---------- the plugin's endpoints

def create(api, t):
    return api.xml("POST", EXT + "/tunnels", to_xml(t)).findtext("id")


def update(api, tid, t):
    return from_xml(api.xml("PUT", f"{EXT}/tunnels/{tid}", to_xml(t)))


def delete(api, tid):
    api.xml("DELETE", f"{EXT}/tunnels/{tid}")


def tunnels(api):
    return {t["id"]: t for t in (from_xml(el) for el in api.xml("GET", EXT + "/tunnels").iter(PKG + "SshTunnel"))}


def statuses(api):
    return {el.findtext("tunnelId"): {"state": el.findtext("state"), "lastError": el.findtext("lastError") or ""}
            for el in api.xml("GET", EXT + "/statuses").iter(PKG + "SshTunnelStatus")}


def wait_state(api, tid, states, timeout=90):
    """Polls until the tunnel's state is one of states. Returns its last status, whether or not it got there."""
    states = (states,) if isinstance(states, str) else states
    end = time.time() + timeout
    while True:
        status = statuses(api).get(tid, {"state": None, "lastError": ""})
        if status["state"] in states or time.time() > end:
            return status
        time.sleep(1)


def events(api, tid):
    """The tunnel's connection history, oldest first: (level, message) pairs."""
    root = api.xml("GET", f"{EXT}/tunnels/{tid}/events")
    return [(el.findtext("level"), el.findtext("message")) for el in root.iter(PKG + "TunnelEvent")]


def wait_event(api, tid, text, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if any(text in (message or "") for _, message in events(api, tid)):
            return True
        time.sleep(1)
    return False


def start(api, tid):
    api.xml("POST", f"{EXT}/tunnels/{tid}/_start")


def stop(api, tid):
    api.xml("POST", f"{EXT}/tunnels/{tid}/_stop")


def test_connection(api, t):
    """The staged diagnostic. Returns (success, {step name: (status, detail)})."""
    root = api.xml("POST", EXT + "/_testConnection", to_xml(t))
    steps = {el.findtext("name"): (el.findtext("status"), el.findtext("detail") or "")
             for el in root.iter(PKG + "DiagnosticStep")}
    return root.findtext("success") == "true", steps


def fetch_host_key(api, port):
    root = api.xml("POST", EXT + "/_fetchHostKey", query={"host": "127.0.0.1", "port": port})
    return {field: root.findtext(field) for field in ("keyType", "fingerprint", "publicKey")}


def _string(path, status, text):
    """An endpoint that returns a String: the engine sends it as the text itself, or wrapped in <string>."""
    if status != 200:
        raise ApiError(f"{path} -> HTTP {status}: {text[:300]}")
    return (ET.fromstring(text).text or "") if text.lstrip().startswith("<string") else text


def derive_public_key(api, t):
    return _string("_derivePublicKey", *api.request("POST", EXT + "/_derivePublicKey", to_xml(t)))


def reveal_key(api, tid):
    return _string("_revealKey", *api.request("POST", f"{EXT}/tunnels/{tid}/_revealKey"))


def plugin_events(api, limit=200):
    """The plugin's entries in the engine's event log, newest first: each one's attributes."""
    found = []
    for event in api.xml("GET", "/events", query={"limit": limit}):
        if event.findtext("name") == "SSH Tunnel Manager":
            found.append({entry[0].text: entry[1].text for entry in event.iter("entry")})
    return found


# ---------- users and rbac roles

def create_user(api, username, password):
    """Creates an engine user and sets its password. Returns the user's id."""
    user = ET.Element("user")
    for tag, text in (("username", username), ("firstName", "SSH"), ("lastName", "e2e"),
                      ("email", f"{username}@example.com")):
        ET.SubElement(user, tag).text = text
    api.xml("POST", "/users", ET.tostring(user, encoding="unicode"))
    uid = api.xml("GET", f"/users/{username}").findtext("id")
    status, text = api.request("PUT", f"/users/{uid}/password", password, content_type="text/plain")
    if status not in (200, 204) or "<string>" in text:   # a list of strings is the password rules it broke
        raise ApiError(f"PUT /users/{uid}/password -> HTTP {status}: {text[:300]}")
    return uid


RBAC = "/extensions/rbac"


def rbac_answers(api):
    """rbac is installed and running: its role list answers."""
    return api.request("GET", RBAC + "/roles")[0] == 200


def create_role(api, name, permissions, channel_ids=()):
    """An rbac role. An empty channel_ids leaves the role unrestricted by channel. Returns the role's id."""
    role = ET.Element("com.diridium.rbac.Role")
    ET.SubElement(role, "name").text = name
    ET.SubElement(role, "description").text = "oie-ssh-tunnel-manager e2e"
    for tag, values in (("permissions", permissions), ("channelIds", channel_ids)):
        holder = ET.SubElement(role, tag)
        for value in values:
            ET.SubElement(holder, "string").text = value
    ET.SubElement(role, "isAdmin").text = "false"
    return api.xml("POST", RBAC + "/roles", ET.tostring(role, encoding="unicode")).findtext("id")


def assign_role(api, user_id, role_id):
    api.xml("POST", f"{RBAC}/users/{user_id}/role/{role_id}")


# ---------- extensions

def install(api, zip_path):
    with open(zip_path, "rb") as f:
        payload = f.read()
    status, text = api.multipart("/extensions/_install",
                                 [("file", os.path.basename(zip_path), "application/zip", payload)])
    return status in (200, 204), f"HTTP {status} {text[:200]}"


def uninstall(api):
    # The engine writes the body verbatim into extensions/uninstall, so it is the bare path:
    # an XML-wrapped <string> is written literally and matches no extension folder.
    status, text = api.request("POST", "/extensions/_uninstall", PLUGIN_PATH)
    return status in (200, 204), f"HTTP {status} {text[:200]}"


def plugin_installed(api):
    root = api.xml("GET", "/extensions/plugins")
    return any(el.get("path") == PLUGIN_PATH for el in root.iter("pluginMetaData"))
