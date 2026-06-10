"""Regression tests for nsmwebng, covering bugs found in the Phase B adversarial
review.  Pure-Python (no network, no node) so they run anywhere.

Run: python3 -m pytest tests/test_nsmwebng_regression.py
 or: python3 tests/test_nsmwebng_regression.py
"""
import difflib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nosqlmap import nsmwebng as w


class _P:
    def __init__(self, body="", status=200):
        self.body = body
        self.status = status


class _C:
    """Minimal Ctx stand-in for the assertion oracle."""
    def __init__(self, **kw):
        self.assert_true = kw.get("assert_true")
        self.assert_false = kw.get("assert_false")
        self.assert_code = kw.get("assert_code")
        self.assert_regex = kw.get("assert_regex")


# --- Fix #1: a malformed --trueRegex must not crash the oracle ----------------
def test_bad_regex_does_not_crash():
    assert w._asserted(_C(assert_regex=re.compile("Welcome")), _P("Welcome back")) is True
    assert w._asserted(_C(assert_regex=re.compile("Welcome")), _P("nope")) is False
    # a raw, never-compiled bad pattern degrades to None (fuzzy fallback), no raise
    assert w._asserted(_C(assert_regex="("), _P("x")) is None


# --- Fix #6: typed exclusion values coerce to numbers for $nin ----------------
def test_typed_excl_coercion():
    assert w._typed_excl(["42", "7", "foo", None]) == [42, 7]


# --- Fix #2 / #8: raw-request query params + multi-value fidelity -------------
def test_query_params_preserved_and_marker_in_query():
    raw = ("POST /search?tenant=acme&page=2 HTTP/1.1\nHost: h:80\n"
           "Content-Type: application/x-www-form-urlencoded\n\nq=hello&sort=asc")
    t = w.parse_raw_request(raw)
    assert t["base_url"] == "http://h:80/search"
    assert set(t["param_fields"]) == {"tenant", "page"}
    assert t["fields"] == {"q": "hello", "sort": "asc", "tenant": "acme", "page": "2"}

    raw2 = ("POST /login?u=* HTTP/1.1\nHost: h\n"
            "Content-Type: application/x-www-form-urlencoded\n\npassword=x")
    t2 = w.parse_raw_request(raw2)
    assert t2["inject_fields"] == ["u"]


def test_duplicate_params_become_list():
    raw = ("POST /x HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\n"
           "a=1&a=2&roles=x&roles=y&b=9")
    t = w.parse_raw_request(raw)
    assert t["fields"] == {"a": ["1", "2"], "roles": ["x", "y"], "b": "9"}
    form = w._build_form({k: ("lit", v) for k, v in t["fields"].items()})
    assert form["a"] == ["1", "2"] and form["roles"] == ["x", "y"]


# --- Fix #9 / #10: JSON structure round-trips faithfully ---------------------
def _roundtrip(obj):
    t = w.parse_raw_request("POST /api HTTP/1.1\nHost: h\nContent-Type: application/json\n\n"
                            + json.dumps(obj))
    spec = {k: ("lit", v) for k, v in t["fields"].items()}
    return w._build_json(spec, t["json_template"], t["json_segmap"])


def test_numeric_string_keys_stay_object():
    assert _roundtrip({"items": {"0": "a", "1": "b"}, "user": "bob"}) == \
        {"items": {"0": "a", "1": "b"}, "user": "bob"}


def test_real_array_stays_array():
    assert _roundtrip({"items": ["a", "b"], "m": {"k": "v"}}) == \
        {"items": ["a", "b"], "m": {"k": "v"}}


def test_dotted_key_not_renested():
    assert _roundtrip({"a.b": 1, "c": {"d": 2}}) == {"a.b": 1, "c": {"d": 2}}


def test_leaf_injection_keeps_structure():
    t = w.parse_raw_request("POST /api HTTP/1.1\nHost: h\nContent-Type: application/json\n\n"
                            + json.dumps({"a.b": 1, "c": {"d": 2}}))
    spec = {k: ("lit", v) for k, v in t["fields"].items()}
    spec["a.b"] = ("ops", {"$ne": "zz"})
    assert w._build_json(spec, t["json_template"], t["json_segmap"]) == \
        {"a.b": {"$ne": "zz"}, "c": {"d": 2}}


def test_build_json_fallback_without_template():
    assert w._build_json({"filter.user": ("lit", "bob"), "q": ("lit", "x")}) == \
        {"filter": {"user": "bob"}, "q": "x"}


# --- Fix #4: dynamic-stripping preserves a short static signal island ---------
def test_dynamic_strip_preserves_signal_island():
    head = "<table class=q><thead><tr><th>Results of your search</th></tr></thead>"
    tail = "</tbody></table><div class=pager>page 1 of 1</div></body></html>"
    island = "</thead><tbody><tr><td>"

    def page(t1, t2, row):
        return head + "<!--n:" + t1 + "-->" + island + row + "</td></tr><!--t:" + t2 + "-->" + tail

    a = page("a1b2c3d4e5f6a1b2", "z9y8x7w6v5u4z9y8", "")
    b = page("00112233445566aa", "ffeeddccbbaa9988", "")
    markings = w._find_dynamic(a, b)
    # two no-match baselines collapse to identical (dynamic tokens stripped)
    assert w._apply_dynamic(a, markings) == w._apply_dynamic(b, markings)
    # but TRUE (row present) vs FALSE (no row) remain distinguishable
    true_p = page("111aaa222bbb333c", "444ddd555eee666f", "<b>secretuser</b>")
    false_p = page("999zzz888yyy777x", "666www555vvv444u", "")
    st = w._apply_dynamic(true_p, markings)
    sf = w._apply_dynamic(false_p, markings)
    assert "secretuser" in st and "secretuser" not in sf
    assert difflib.SequenceMatcher(None, st, sf).quick_ratio() < 0.95


def test_single_dynamic_region_unchanged():
    head, tail = "X" * 60, "Y" * 60
    a = head + "<csrf=aaaa1111bbbb2222>" + tail
    b = head + "<csrf=zzzz9999wwww8888>" + tail
    m = w._find_dynamic(a, b)
    assert len(m) == 1
    assert w._apply_dynamic(a, m) == w._apply_dynamic(b, m)
    assert w._find_dynamic("A" * 100, "A" * 100) == []


# --- Fix #7: --timeDelay 0 is floored so the time oracle can't run on noise ---
def test_time_detect_rejects_nonpositive_delay():
    assert w._detect_time(w.Ctx(), "POST", "http://x/", {"u": "x"}, ["form"], 0) == []


# --- Phase C: length pre-probe -----------------------------------------------
def _oracle(secret):
    return lambda pat: re.search(pat, secret) is not None


def test_value_length():
    assert w._value_length(_oracle("hello"), 64) == 5
    assert w._value_length(_oracle(""), 64) == 0
    assert w._value_length(_oracle("abc"), 2) == 2          # capped at maxlen


# --- Phase C: walk resume (start prefix) + known length + checkpoint ---------
def test_walk_resume_and_checkpoint():
    secret = "Secret_42"
    charset = "".join(sorted(set(secret)))
    seen = []
    v = w._walk_value(_oracle(secret), charset, 64, start="Sec",
                      length=len(secret), on_char=seen.append)
    assert v == secret
    assert seen and seen[-1] == secret          # checkpoint fired, last == full value
    assert all(secret.startswith(s) for s in seen)   # monotonic prefixes


# --- Phase C: pin clause keeps record fields on one document -----------------
def test_pin_js():
    assert w._pin_js({"username": "alice"}) == ' && String(this.username)==="alice"'
    assert w._pin_js(None) == ""


# --- Phase C: session store roundtrip + resume + flush + no_resume -----------
def test_store_roundtrip():
    import tempfile
    import shutil
    from nosqlmap import nsmstore
    d = tempfile.mkdtemp()
    try:
        s = nsmstore.Store("http://t/login", output_dir=d)
        ck = nsmstore.context_key({"field": "u", "pin": [], "exclude": []})
        assert s.get_value(ck) is None
        s.set_partial(ck, "u", "ali", False)            # partial
        assert s.get_value(ck)["complete"] is False
        s.set_partial(ck, "u", "alice", True, 5)        # complete
        assert s.get_value(ck) == {"value": "alice", "complete": True, "length": 5}
        s.close()

        # a no_resume Store ignores the saved value
        s2 = nsmstore.Store("http://t/login", output_dir=d, no_resume=True)
        assert s2.get_value(ck) is None
        s2.close()

        # flush clears it
        s3 = nsmstore.Store("http://t/login", output_dir=d, flush=True)
        assert s3.get_value(ck) is None
        s3.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_context_key_stable_and_distinct():
    from nosqlmap import nsmstore
    a = nsmstore.context_key({"field": "u", "pin": [("x", "1")], "exclude": ["a"]})
    b = nsmstore.context_key({"exclude": ["a"], "pin": [("x", "1")], "field": "u"})
    c = nsmstore.context_key({"field": "u", "pin": [("x", "1")], "exclude": ["a", "b"]})
    assert a == b          # key order independent
    assert a != c          # different exclude -> different key


# --- Phase C review fixes ----------------------------------------------------
# C1: a stale resumed prefix that no longer matches the live oracle is discarded
def test_walk_discards_stale_prefix_via_revalidation():
    secret = "root"
    charset = "".join(sorted(set(secret + "adm")))
    # Caller's job (extract.walk) is to discard a stale start when the prefix no
    # longer matches; emulate that guard and confirm the walk then recovers live.
    stale = "adm"
    if not _oracle(secret)("^" + re.escape(stale)):
        stale = ""
    assert stale == ""     # "adm" is not a prefix of "root" -> discarded
    assert w._walk_value(_oracle(secret), charset, 64, start=stale) == secret


# C3: typed booleans stringify to JS-canonical lowercase (so pin matching works)
def test_typed_str_boolean_canonical():
    assert w._typed_str(True) == "true"
    assert w._typed_str(False) == "false"
    assert w._typed_str(42) == "42"
    assert w._pin_js({"isAdmin": w._typed_str(True)}) == ' && String(this.isAdmin)==="true"'


# C2: Ctx.clone gives a fresh Session but copies config + learned dynamic regions
def test_ctx_clone_independent_session():
    base = w.Ctx(headers={"X": "1"}, verify=True, cookies={"s": "1"})
    base.dynamic = [("pre", "suf")]
    c = base.clone()
    assert c.session is not base.session          # own Session (thread-safe)
    assert c.headers == base.headers and c.verify == base.verify
    assert c.cookies == base.cookies
    assert c.dynamic == base.dynamic and c.dynamic is not base.dynamic


# C5: data.csv is rewritten even when a run recovers no records (no stale rows)
def test_csv_truncated_on_empty_run():
    import tempfile
    import shutil
    from nosqlmap import nsmstore
    d = tempfile.mkdtemp()
    try:
        s = nsmstore.Store("http://t/x", output_dir=d)
        s.write_records(["a", "b"], [{"a": "1", "b": "2"}])
        s.write_records(["a", "b"], [])          # empty run must not keep old rows
        s.close()
        rows = open(s.csv_path).read().strip().splitlines()
        assert rows == ["a,b"], rows               # header only, stale row gone
    finally:
        shutil.rmtree(d, ignore_errors=True)


# C7: --flushSession clears the streamed output files, not just the sqlite rows
def test_flush_clears_output_files():
    import os
    import tempfile
    import shutil
    from nosqlmap import nsmstore
    d = tempfile.mkdtemp()
    try:
        s = nsmstore.Store("http://t/x", output_dir=d)
        s.record_value("u", "alice")
        s.save_finding({"label": "L", "vector": "form"}, "u[$ne]=x")
        s.close()
        assert os.path.getsize(os.path.join(d, "data.ndjson")) > 0
        s2 = nsmstore.Store("http://t/x", output_dir=d, flush=True)
        s2.close()
        assert not os.path.exists(os.path.join(d, "data.ndjson"))
        assert not os.path.exists(os.path.join(d, "findings.ndjson"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok  %s" % fn.__name__)
    print("\nall %d regression tests passed" % len(fns))
