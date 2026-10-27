#!/usr/bin/env python3
"""Stage-1 coarse screener: fetch subscriptions, test each node via Mihomo,
emit survivors as ORIGINAL share links (verbatim: filtered, never converted).

Design rules:
- Output lines are the input lines, unchanged, so v2rayN import loses no
  parameters. Mihomo YAML is only used internally for testing.
- Coarse filter = liveness only: any measured delay keeps the node. Speed
  ranking is stage 2 (the user's PC), because Singapore delay does not
  represent Qingdao Unicom delay.
- Links this tester cannot parse (xhttp, anytls, ss plugins, ...) go to the
  untested bucket with a reason in report.json, never silently dropped.
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DATA = os.environ.get("DATA_DIR", "/app/data")
MIHOMO = os.environ.get("MIHOMO_BIN", "mihomo")
TEST_URL = "http://www.gstatic.com/generate_204"

SUPPORTED_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
}


# ---------------------------------------------------------------- fetching
def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "node-screener/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def decode_sub(text):
    """A subscription body is either plain link lines or one base64 blob."""
    text = text.strip()
    if not text:
        return []
    if "://" not in text:
        try:
            padded = text + "=" * (-len(text) % 4)
            text = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
        except Exception:
            pass
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and "://" in ln and not ln.strip().startswith("#")]


# ---------------------------------------------------------------- parsing
def _q(query):
    return dict(urllib.parse.parse_qsl(query))


def _un(s):
    return urllib.parse.unquote(s or "")


def parse_vless(line):
    u = urllib.parse.urlparse(line)
    q = _q(u.query)
    uuid, host, port = _un(u.username), u.hostname or "", u.port or 0
    if not uuid or not host or not port:
        return None, "vless missing uuid/host/port"
    ntype = (q.get("type") or "tcp").lower()
    # Pool generators emit type=raw for plain-TCP Reality nodes (verified
    # against the radikal cleaned files: raw + encryption=none + pbk/sid).
    # Mihomo has no "raw" network; tcp is the equivalent transport.
    if ntype == "raw":
        ntype = "tcp"
    if ntype not in ("tcp", "ws", "grpc", "xhttp"):
        return None, "vless network %s not covered" % ntype
    security = (q.get("security") or "none").lower()
    if security not in ("none", "tls", "reality"):
        return None, "vless security %s not covered" % security
    enc = q.get("encryption")
    if enc and enc != "none":
        return None, "vless encryption %s not covered" % enc
    flow = q.get("flow") or ""
    if flow and flow != "xtls-rprx-vision":
        return None, "vless flow %s not covered" % flow
    if flow and ntype != "tcp":
        return None, "vision flow requires tcp"
    p = {"type": "vless", "server": host, "port": port, "uuid": uuid, "network": ntype}
    if security in ("tls", "reality"):
        p["tls"] = True
        if q.get("sni"):
            p["servername"] = q["sni"]
        if q.get("fp"):
            p["fingerprint"] = q["fp"]
        if q.get("allowInsecure") == "1":
            p["skip-cert-verify"] = True
        if security == "reality":
            if not q.get("pbk"):
                return None, "reality without public key"
            p["reality-opts"] = {"public-key": q["pbk"], "short-id": q.get("sid", "")}
    if ntype == "ws":
        opts = {"path": q.get("path", "/")}
        if q.get("host"):
            opts["headers"] = {"Host": q["host"]}
        p["ws-opts"] = opts
    if ntype == "grpc":
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    if ntype == "xhttp":
        # Mihomo 1.19+ supports xhttp (wiki: xhttp-opts {path, host, mode});
        # our pinned Mihomo is 1.19.33.
        opts = {"path": q.get("path", "/")}
        if q.get("host"):
            opts["host"] = q["host"]
        if q.get("mode") in ("stream-one", "stream-up", "packet-up"):
            opts["mode"] = q["mode"]
        p["xhttp-opts"] = opts
    if q.get("alpn"):
        p["alpn"] = [a for a in q["alpn"].split(",") if a]
    if flow:
        p["flow"] = flow
    return p, None


def parse_vmess(line):
    # Some pools append a #fragment tag after the base64 (e.g. #@VPsave);
    # strip it before decoding or padding checks fail.
    raw = line[len("vmess://"):].strip().split("#", 1)[0]
    padded = raw + "=" * (-len(raw) % 4)
    try:
        j = json.loads(base64.b64decode(padded))
    except Exception:
        j = json.loads(base64.urlsafe_b64decode(padded))
    net = (j.get("net") or "tcp").lower()
    if net not in ("tcp", "ws", "grpc"):
        return None, "vmess net %s not covered" % net
    try:
        port = int(j.get("port", 0))
        aid = int(j.get("aid", 0))
    except (TypeError, ValueError):
        return None, "vmess bad port/aid"
    p = {"type": "vmess", "server": j.get("add", ""), "port": port,
         "uuid": j.get("id", ""), "alterId": aid,
         "cipher": j.get("scy", "auto"), "network": net}
    if not p["server"] or not p["port"] or not p["uuid"]:
        return None, "vmess missing fields"
    if str(j.get("tls", "")).lower() == "tls":
        p["tls"] = True
        if j.get("sni"):
            p["servername"] = j["sni"]
        if j.get("fp"):
            p["fingerprint"] = j["fp"]
    if net == "ws":
        opts = {"path": j.get("path", "/")}
        if j.get("host"):
            opts["headers"] = {"Host": j["host"]}
        p["ws-opts"] = opts
    if net == "grpc":
        p["grpc-opts"] = {"grpc-service-name": j.get("path", "")}
    return p, None


def parse_trojan(line):
    u = urllib.parse.urlparse(line)
    q = _q(u.query)
    pw, host, port = _un(u.username), u.hostname or "", u.port or 0
    if not pw or not host or not port:
        return None, "trojan missing fields"
    ntype = (q.get("type") or "tcp").lower()
    if ntype not in ("tcp", "ws", "grpc"):
        return None, "trojan network %s not covered" % ntype
    p = {"type": "trojan", "server": host, "port": port, "password": pw, "network": ntype}
    if q.get("sni"):
        p["sni"] = q["sni"]
    if q.get("allowInsecure") == "1":
        p["skip-cert-verify"] = True
    if q.get("fp"):
        p["fingerprint"] = q["fp"]
    if ntype == "ws":
        opts = {"path": q.get("path", "/")}
        if q.get("host"):
            opts["headers"] = {"Host": q["host"]}
        p["ws-opts"] = opts
    if ntype == "grpc":
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    return p, None


def parse_ss(line):
    rest = line[len("ss://"):]
    if "#" in rest:
        rest = rest.split("#", 1)[0]
    if "?" in rest:
        rest, query = rest.split("?", 1)
        if "plugin" in query:
            return None, "ss plugin not covered"
    userinfo, sep, hostport = rest.rpartition("@")
    if not sep:
        try:
            padded = rest + "=" * (-len(rest) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
        except Exception:
            return None, "ss base64 decode failed"
        return parse_ss("ss://" + decoded)
    if ":" not in userinfo and re.fullmatch(r"[A-Za-z0-9+/=_-]+", userinfo or ""):
        try:
            padded = userinfo + "=" * (-len(userinfo) % 4)
            userinfo = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
        except Exception:
            pass
    if ":" not in userinfo:
        return None, "ss userinfo has no method:password"
    method, password = userinfo.split(":", 1)
    method = method.lower()
    if method not in SUPPORTED_SS_CIPHERS:
        return None, "ss cipher %s not covered" % method
    hostport = hostport.split("/")[0]
    if ":" not in hostport:
        return None, "ss missing host:port"
    host, port = hostport.rsplit(":", 1)
    try:
        port = int(port)
    except ValueError:
        return None, "ss bad port"
    return {"type": "ss", "server": host, "port": port, "cipher": method,
            "password": _un(password)}, None


def parse_hy2(line):
    u = urllib.parse.urlparse(line)
    q = _q(u.query)
    pw, host, port = _un(u.username), u.hostname or "", u.port or 0
    if not pw or not host or not port:
        return None, "hysteria2 missing fields"
    if q.get("ports"):
        return None, "hysteria2 port hopping not covered"
    p = {"type": "hysteria2", "server": host, "port": port, "password": pw}
    if q.get("sni"):
        p["sni"] = q["sni"]
    obfs = q.get("obfs") or "none"
    if obfs != "none":
        if obfs != "salamander":
            return None, "hysteria2 obfs %s not covered" % obfs
        p["obfs"] = "salamander"
        p["obfs-password"] = q.get("obfs-password", "")
    if q.get("insecure") == "1":
        p["skip-cert-verify"] = True
    return p, None


def parse_link(line):
    scheme = line.split("://", 1)[0].lower()
    fn = {"vless": parse_vless, "vmess": parse_vmess, "trojan": parse_trojan,
          "ss": parse_ss, "hysteria2": parse_hy2}.get(scheme)
    if fn is None:
        return None, "unsupported protocol: %s" % scheme
    try:
        return fn(line)
    except Exception as e:  # noqa: BLE001 - surfaced as untested reason
        return None, "parse error: %s" % e


# ---------------------------------------------------------------- mihomo yaml
def yq(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(yq(x) for x in v) + "]"
    return '"%s"' % str(v).replace("\\", "\\\\").replace('"', '\\"')


def emit_map(d, indent):
    lines = []
    for k, v in d.items():
        pad = " " * indent
        if isinstance(v, dict):
            lines.append("%s%s:" % (pad, k))
            lines.extend(emit_map(v, indent + 2))
        else:
            lines.append("%s%s: %s" % (pad, k, yq(v)))
    return lines


def build_config(names, proxies):
    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "external-controller: 127.0.0.1:9090",
        "proxies:",
    ]
    for name, p in zip(names, proxies):
        lines.append("  - name: %s" % yq(name))
        for k, v in p.items():
            if isinstance(v, dict):
                lines.append("    %s:" % k)
                lines.extend(emit_map(v, 6))
            else:
                lines.append("    %s: %s" % (k, yq(v)))
    lines.append("proxy-groups:")
    lines.append('  - name: "PROXIES"')
    lines.append("    type: select")
    lines.append("    proxies:")
    for name in names:
        lines.append("      - %s" % yq(name))
    lines.append("rules:")
    lines.append("  - MATCH,DIRECT")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- testing
def test_one(name):
    url = ("http://127.0.0.1:9090/proxies/%s/delay?timeout=5000&url=%s"
           % (name, urllib.parse.quote(TEST_URL, safe="")))
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=12) as r:
            return json.loads(r.read()).get("delay", 0) or 0
    except Exception:
        return 0


def write_report(report):
    with open(os.path.join(DATA, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def main():
    os.makedirs(DATA, exist_ok=True)
    urls = [u.strip() for u in os.environ.get("SUB_URLS", "").split(",") if u.strip()]
    report = {"sub_urls": urls, "total": 0, "testable": 0, "survivors": 0,
              "untested": 0, "failed": 0, "delays": {}, "untested_reasons": {}}
    if not urls:
        report["error"] = "SUB_URLS is empty"
        write_report(report)
        return 2
    raw_lines = []
    for url in urls:
        try:
            raw_lines.extend(decode_sub(fetch_text(url)))
        except Exception as e:  # noqa: BLE001 - recorded, run continues
            report.setdefault("fetch_errors", {})[url] = str(e)
    uniq = list(dict.fromkeys(raw_lines))
    report["total"] = len(uniq)
    names, proxies, mapping = [], [], {}
    untested = []
    seen_keys = set()
    for ln in uniq:
        p, reason = parse_link(ln)
        if p is None:
            untested.append(ln)
            report["untested_reasons"][ln] = reason
            continue
        key = (p["type"], p["server"], p["port"], p.get("uuid") or p.get("password") or "")
        if key in seen_keys:
            continue
        seen_keys.add(key)
        name = "n%04d" % len(names)
        names.append(name)
        proxies.append(p)
        mapping[name] = ln
    delays = {}
    if names:
        cfg = os.path.join(DATA, "mihomo.yaml")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write(build_config(names, proxies))
        proc = subprocess.Popen([MIHOMO, "-d", DATA, "-f", cfg],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(3)  # let the controller come up
            if proc.poll() is None:
                with ThreadPoolExecutor(max_workers=20) as ex:
                    for name, d in zip(names, ex.map(test_one, names)):
                        delays[name] = d
            else:
                report["mihomo_error"] = "mihomo exited early rc=%s" % proc.returncode
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
    survivors, failed = [], 0
    for name in names:
        d = delays.get(name, 0)
        report["delays"][name] = d
        if d and d > 0:
            survivors.append(mapping[name])
        else:
            failed += 1
    report["testable"] = len(names)
    report["survivors"] = len(survivors)
    report["failed"] = failed
    report["untested"] = len(untested)
    with open(os.path.join(DATA, "survivors.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(survivors) + ("\n" if survivors else ""))
    with open(os.path.join(DATA, "untested.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(untested) + ("\n" if untested else ""))
    write_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
