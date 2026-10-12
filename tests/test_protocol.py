import hashlib, json, random
import pytest

from wf_peering.protocol import canonical as cj, merkle, keylog, actions, integrity, netpolicy, trust, entries
from wf_peering.protocol.signing import Signer, b64encode, fingerprint
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def x25519_pub() -> str:
    return b64encode(X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))



def test_canonical_sorts_keys_and_drops_whitespace():
    assert cj.canonical({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'


def test_canonical_escapes_minimally_and_keeps_unicode():
    assert cj.canonical_text({"k": "ä\n\"\\\u0001"}) == '{"k":"ä\\n\\"\\\\\\u0001"}'


@pytest.mark.parametrize("value", [1.5, {"a": float("nan")}, 2 ** 53, {1: "x"}, {"ü": 1}, "\ud800", object()])
def test_canonical_rejects_non_canonical_values(value):
    with pytest.raises(cj.CanonicalError):
        cj.canonical(value)


def test_canonical_is_stable_across_key_order():
    one = {"z": {"b": [1, 2], "a": "x"}, "a": None}
    two = json.loads(json.dumps({"a": None, "z": {"a": "x", "b": [1, 2]}}))
    assert cj.digest(one) == cj.digest(two)



def brute_root(leaves):
    if not leaves: return hashlib.sha256(b"").hexdigest()
    if len(leaves) == 1: return leaves[0]
    k = 1
    while k * 2 < len(leaves): k *= 2
    return merkle.node_hash(brute_root(leaves[:k]), brute_root(leaves[k:]))


@pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 33])
def test_merkle_root_matches_reference_and_proofs_verify(size):
    leaves = [merkle.leaf_hash(f"leaf-{i}".encode()) for i in range(size)]
    value = merkle.root(leaves)
    assert value == brute_root(leaves)
    for index in range(size):
        proof = merkle.inclusion_proof(index, leaves)
        assert merkle.verify_inclusion(index, size, leaves[index], proof, value)
        assert not merkle.verify_inclusion(index, size, merkle.leaf_hash(b"other"), proof, value)
    for first in range(1, size + 1):
        proof = merkle.consistency_proof(first, leaves)
        assert merkle.verify_consistency(first, size, merkle.root(leaves[:first]), value, proof)
        if first < size:
            assert not merkle.verify_consistency(first, size, merkle.leaf_hash(b"x"), value, proof)


def test_merkle_detects_any_changed_leaf():
    leaves = [merkle.leaf_hash(bytes([i])) for i in range(10)]
    base = merkle.root(leaves)
    for index in range(10):
        changed = list(leaves)
        changed[index] = merkle.leaf_hash(b"tampered")
        assert merkle.root(changed) != base


def test_known_empty_and_single_roots():
    assert merkle.root([]) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert merkle.root([merkle.leaf_hash(b"")]) == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"



def test_entry_problems_and_link_checks():
    content = entries.make(1, entries.GENESIS, "peering:genesis", "peering", {"a": 1}, ts="2026-10-09T00:00:00Z")
    assert entries.problems(content) == []
    assert entries.check_link(content, entries.GENESIS, 0) == []
    second = entries.make(3, "f" * 64, "peering:x", "peering", {}, ts="2026-10-09T00:00:01Z")
    assert set(entries.check_link(second, entries.entry_hash(content), 1)) == {"SEQUENCE_GAP", "BROKEN_CHAIN"}
    bad = dict(content, kind="NoColon", extra=1)
    assert "INVALID_KIND" in entries.problems(bad) and "UNEXPECTED_FIELDS" in entries.problems(bad)


def test_entry_hash_signature_roundtrip():
    signer = Signer.generate()
    content = entries.make(1, entries.GENESIS, "peering:genesis", "peering", {})
    value = entries.entry_hash(content)
    signature = entries.sign_hash(signer, entries.LEDGER_CONTEXT, value)
    assert entries.verify_hash(signer.public_key, entries.LEDGER_CONTEXT, value, signature)
    assert not entries.verify_hash(signer.public_key, entries.JOURNAL_CONTEXT, value, signature)
    assert not entries.verify_hash(Signer.generate().public_key, entries.LEDGER_CONTEXT, value, signature)



HANDLE = keylog.account_handle("https://host.example", 7)


class Account:
    def __init__(self):
        self.envelopes = []
        self.head = keylog.GENESIS

    def statement(self, kind, authority, keys, reset=None):
        statement = {"v": 1, "account": HANDLE, "seq": len(self.envelopes) + 1, "prev": self.head,
                     "type": kind, "authority": authority, "keys": keys, "ts": 1760000000 + len(self.envelopes)}
        if reset is not None: statement["reset"] = reset
        return statement

    def add(self, statement, subject=None, authority=None):
        envelope = {"protocol": keylog.PROTOCOL, "statement": statement, "signatures": {
            "subject": subject.sign(keylog.SUBJECT_CONTEXT, statement) if subject else None,
            "authority": authority.sign(keylog.AUTHORITY_CONTEXT, statement) if authority else None
        }}
        self.envelopes.append(envelope)
        self.head = keylog.statement_hash(statement)
        return envelope


def device_keys(signer):
    return {"sig": signer.public_key, "enc": x25519_pub()}


def test_handle_is_stable_and_origin_normalized():
    assert keylog.account_handle("HTTPS://Host.Example/", 7) == HANDLE
    assert keylog.account_handle("https://host.example", 8) != HANDLE
    assert keylog.valid_handle(HANDLE)


def test_first_binding_rotation_and_recovery_are_valid():
    account = Account()
    first, second, third, recovery, recovery2 = (Signer.generate() for _ in range(5))
    account.add(account.statement("device.bind", "self", device_keys(first)), subject=first)
    account.add(account.statement("recovery.set", "device", {"recovery": recovery.public_key}),
                subject=recovery, authority=first)
    account.add(account.statement("device.bind", "device", device_keys(second)), subject=second, authority=first)
    account.add(account.statement("device.bind", "recovery", device_keys(third)), subject=third, authority=recovery)
    account.add(account.statement("recovery.set", "recovery", {"recovery": recovery2.public_key}),
                subject=recovery2, authority=recovery)
    state, verdicts = keylog.replay(HANDLE, account.envelopes)
    assert all(verdict.valid for verdict in verdicts)
    assert state.device["sig"] == third.public_key and state.recovery == recovery2.public_key
    assert not state.broken and not [f for f in state.flags if f.severity == "critical"]


def test_unauthorized_key_change_by_host_is_critical():
    account = Account()
    first, intruder = Signer.generate(), Signer.generate()
    account.add(account.statement("device.bind", "self", device_keys(first)), subject=first)
    account.add(account.statement("device.bind", "host", device_keys(intruder)), subject=intruder)
    state, verdicts = keylog.replay(HANDLE, account.envelopes)
    assert verdicts[1].valid and any(f.code == "HOST_ASSERTED_KEY_CHANGE" and f.severity == "critical"
                                     for f in verdicts[1].flags)
    assert state.device["sig"] == intruder.public_key


def test_forged_authority_signature_breaks_the_chain():
    account = Account()
    first, intruder = Signer.generate(), Signer.generate()
    account.add(account.statement("device.bind", "self", device_keys(first)), subject=first)
    account.add(account.statement("device.bind", "device", device_keys(intruder)), subject=intruder, authority=intruder)
    state, verdicts = keylog.replay(HANDLE, account.envelopes)
    assert not verdicts[1].valid and verdicts[1].flags[0].code == "INVALID_AUTHORITY_SIGNATURE"
    assert state.broken and state.device["sig"] == first.public_key


def test_self_authority_on_anchored_account_and_bad_proof_of_possession():
    account = Account()
    first, other = Signer.generate(), Signer.generate()
    account.add(account.statement("device.bind", "self", device_keys(first)), subject=first)
    account.add(account.statement("device.bind", "self", device_keys(other)), subject=other)
    _, verdicts = keylog.replay(HANDLE, account.envelopes)
    assert verdicts[1].flags[0].code == "SELF_AUTHORITY_ON_ANCHORED_ACCOUNT"

    fresh = Account()
    fresh.add(fresh.statement("device.bind", "self", device_keys(first)), subject=other)
    _, verdicts = keylog.replay(HANDLE, fresh.envelopes)
    assert verdicts[0].flags[0].code == "INVALID_SUBJECT_SIGNATURE"


def test_keylog_gap_and_wrong_account():
    account = Account()
    first = Signer.generate()
    statement = account.statement("device.bind", "self", device_keys(first))
    statement["seq"] = 2
    account.add(statement, subject=first)
    _, verdicts = keylog.replay(HANDLE, account.envelopes)
    assert verdicts[0].flags[0].code == "KEYLOG_CHAIN_BROKEN"
    _, verdicts = keylog.replay(keylog.account_handle("https://other.example", 7), account.envelopes)
    assert verdicts[0].flags[0].code == "ACCOUNT_MISMATCH"


def test_legacy_genesis_and_browser_binding():
    account = Account()
    device, recovery = Signer.generate(), Signer.generate()
    account.add(account.statement("device.bind", "legacy", device_keys(device)), subject=device)
    state, verdicts = keylog.replay(HANDLE, account.envelopes)
    assert verdicts[0].valid and verdicts[0].flags[0].code == "LEGACY_IMPORT"

    browser = Account()
    browser.add(browser.statement("recovery.set", "self", {"recovery": recovery.public_key}), subject=recovery)
    browser.add(browser.statement("browser.bind", "recovery", {"enc": x25519_pub()}), authority=recovery)
    state, verdicts = keylog.replay(HANDLE, browser.envelopes)
    assert all(v.valid for v in verdicts) and len(state.browsers) == 1
    browser.add(browser.statement("device.bind", "recovery", device_keys(device)), subject=device, authority=recovery)
    state, verdicts = keylog.replay(HANDLE, browser.envelopes)
    assert verdicts[-1].valid and state.browsers == [] and state.device["sig"] == device.public_key



def make_action(signer, seq, prev, params, action_id=None, target="users:profile", iat=1760000000):
    return {"v": 1, "account": HANDLE, "device": fingerprint(signer.public_key), "action": "users:profile.set",
            "target": target, "params": params, "id": action_id or b64encode(random.randbytes(16)), "seq": seq,
            "prev": prev, "iat": iat, "exp": iat + 300}


def envelope(signer, action, result_state=None):
    data = {"protocol": actions.PROTOCOL, "action": action, "signature": signer.sign(actions.CONTEXT, action)}
    if result_state is not None: data["result"] = {"state": result_state}
    return data


def bound(signer):
    account = Account()
    account.add(account.statement("device.bind", "self", device_keys(signer)), subject=signer)
    state, _ = keylog.replay(HANDLE, account.envelopes)
    return state


def test_valid_action_is_deterministically_verified():
    device = Signer.generate()
    keys, state = bound(device), actions.ActionState()
    params = {"replace": True, "set": {"first_name": cj.text_commitment("e1.abc")}}
    expected = actions.state_digest(actions.reduce(None, params))
    flags, info = actions.evaluate(keys, state, envelope(device, make_action(device, 1, actions.GENESIS, params), expected),
                                   recorded_at=1760000010)
    assert flags == [] and info["execution"] == "deterministic"


def test_invalid_signature_tampered_params_and_foreign_key():
    device, intruder = Signer.generate(), Signer.generate()
    keys = bound(device)
    action = make_action(device, 1, actions.GENESIS, {"set": {"a": "1"}})
    data = envelope(device, action)
    data["action"] = dict(action, params={"set": {"a": "2"}})
    flags, _ = actions.evaluate(keys, actions.ActionState(), data)
    assert flags[0].code == "INVALID_ACTION_SIGNATURE"

    flags, _ = actions.evaluate(keys, actions.ActionState(), envelope(intruder, make_action(intruder, 1, actions.GENESIS, {"set": {}})))
    assert flags[0].code == "FOREIGN_DEVICE_KEY"

    forged = make_action(intruder, 1, actions.GENESIS, {"set": {}})
    forged["device"] = fingerprint(device.public_key)
    flags, _ = actions.evaluate(keys, actions.ActionState(), envelope(intruder, forged))
    assert flags[0].code == "INVALID_ACTION_SIGNATURE"


def test_missing_signature_replay_gap_and_fork():
    device = Signer.generate()
    keys, state = bound(device), actions.ActionState()
    first = make_action(device, 1, actions.GENESIS, {"set": {"a": "1"}})
    flags, _ = actions.evaluate(keys, state, {"protocol": actions.PROTOCOL, "action": first})
    assert flags[0].code == "INVALID_ACTION_SIGNATURE"

    flags, info = actions.evaluate(keys, state, envelope(device, first))
    assert info["valid"]
    flags, _ = actions.evaluate(keys, state, envelope(device, first))
    assert flags[-1].code == "ACTION_REPLAY"

    gap = make_action(device, 3, actions.action_hash(first), {"set": {"a": "3"}})
    flags, _ = actions.evaluate(keys, state, envelope(device, gap))
    assert [f.code for f in flags if f.code not in ("RESULT_NOT_REPORTED", "BASELINE_UNKNOWN")] == ["ACTION_SEQUENCE_GAP"]

    fork = make_action(device, 4, "a" * 64, {"set": {"a": "4"}})
    flags, _ = actions.evaluate(keys, state, envelope(device, fork))
    assert [f.code for f in flags if f.code not in ("RESULT_NOT_REPORTED", "BASELINE_UNKNOWN")] == ["ACTION_CHAIN_FORK"]

    reused = make_action(device, 2, actions.action_hash(first), {"set": {"a": "x"}})
    flags, _ = actions.evaluate(keys, state, envelope(device, reused))
    assert flags[-1].code == "ACTION_SEQUENCE_REUSED"


def test_result_mismatch_and_validity_window():
    device = Signer.generate()
    keys, state = bound(device), actions.ActionState()
    action = make_action(device, 1, actions.GENESIS, {"replace": True, "set": {"a": "1"}})
    flags, info = actions.evaluate(keys, state, envelope(device, action, "0" * 64), recorded_at=1760000000 + 5000)
    codes = {f.code for f in flags}
    assert "RESULT_MISMATCH" in codes and "ACTION_OUTSIDE_VALIDITY" in codes and info["execution"] == "mismatch"


def test_action_shape_rejects_long_lifetime():
    device = Signer.generate()
    action = make_action(device, 1, actions.GENESIS, {"set": {}})
    action["exp"] = action["iat"] + 3600
    assert "INVALID_LIFETIME" in actions.shape(action)



def test_integrity_normalization_and_aggregation_keep_grouping():
    good = {"id": "users_e2ee", "additive": "users", "hash": "A" * 64, "version": "v1", "type": "script"}
    groups = integrity.aggregate([[good, {"id": "BAD ID", "hash": "x"}], None, [{"id": "ocean_tar", "additive": "ocean",
                                                                               "algorithm": "sha512", "hash": "b" * 128}]])
    assert [g["provider"] for g in groups] == ["users", "unknown-1", "ocean"]
    assert groups[0]["status"] == "partial" and groups[0]["records"][0]["hash"] == "a" * 64
    assert groups[1]["status"] == "failed"
    assert groups[2]["status"] == "ok"


def test_integrity_fingerprint_ignores_computation_time():
    record = integrity.normalize({"id": "x_y", "hash": "c" * 64, "computed_at": "2026-10-09T00:00:00Z"})
    later = integrity.normalize({"id": "x_y", "hash": "c" * 64, "computed_at": "2026-10-10T00:00:00Z"})
    changed = integrity.normalize({"id": "x_y", "hash": "d" * 64})
    assert integrity.fingerprint(record) == integrity.fingerprint(later) != integrity.fingerprint(changed)


@pytest.mark.parametrize("record,code", [
    ({"id": "a", "hash": "0" * 64}, "INVALID_ID"),
    ({"id": "ok_id", "hash": "0" * 63}, "INVALID_HASH"),
    ({"id": "ok_id", "hash": "0" * 64, "algorithm": "md5"}, "UNSUPPORTED_ALGORITHM"),
    ({"id": "ok_id", "hash": "0" * 64, "url": "https://evil"}, "INVALID_URL"),
    ({"id": "ok_id", "hash": "0" * 64, "provenance": {"status": "trust-me"}}, "INVALID_PROVENANCE"),
])
def test_integrity_rejects_bad_records(record, code):
    with pytest.raises(integrity.IntegrityError, match=code):
        integrity.normalize(record)



@pytest.mark.parametrize("url,code", [
    ("http://peer.example", "HTTPS_REQUIRED"),
    ("https://user:pw@peer.example", "CREDENTIALS_NOT_ALLOWED"),
    ("https://peer.example/path", "ORIGIN_ONLY"),
    ("https://peer.example:8443", "PORT_NOT_ALLOWED"),
    ("https://localhost", "INTERNAL_HOST"),
    ("https://intranet", "INTERNAL_HOST"),
    ("ftp://peer.example", "HTTPS_REQUIRED"),
])
def test_peer_urls_are_validated(url, code):
    with pytest.raises(netpolicy.PolicyError, match=code):
        netpolicy.parse_target(url)


@pytest.mark.parametrize("address,allowed", [
    ("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False), ("169.254.169.254", False),
    ("::1", False), ("fd00::1", False), ("2001:4860:4860::8888", True), ("::ffff:10.0.0.1", False), ("0.0.0.0", False)
])
def test_address_policy_blocks_internal_targets(address, allowed):
    assert netpolicy.address_allowed(address) is allowed


def test_clusters_group_shared_infrastructure():
    groups = netpolicy.clusters({
        "@host": {"addresses": ["203.0.113.10"], "domain": "app.example.com"},
        "a": {"addresses": ["203.0.113.99"], "domain": "peer-a.org"},
        "b": {"addresses": ["198.51.100.1"], "domain": "b.example.com"},
        "c": {"addresses": ["192.0.2.5"], "domain": "c.net", "cert_key": "k1"},
        "d": {"addresses": ["192.0.2.200"], "domain": "d.io"},
        "e": {"addresses": ["100.64.1.1"], "domain": "e.de", "cert_key": "k1"},
    })
    assert ["@host", "a", "b"] in groups
    assert ["c", "d", "e"] in groups



def sig(name, value, severity="normal", category="integrity", weight=10, **kw):
    return trust.Signal(name, category, value, weight, severity, **kw)


def test_score_boundaries_and_levels():
    perfect = [sig(f"s{i}", 100, category=cat) for i, cat in enumerate(trust.CATEGORY_WEIGHTS)]
    assert trust.compute(perfect, 3)["score"] == 100
    assert trust.compute([sig(f"s{i}", 0, category=c) for i, c in enumerate(trust.CATEGORY_WEIGHTS)], 3)["score"] == 0
    middle = trust.compute([sig(f"s{i}", 50, category=c) for i, c in enumerate(trust.CATEGORY_WEIGHTS)], 3)
    assert middle["score"] == 50 and middle["level"] == "warning"


def test_critical_failure_caps_an_otherwise_good_score():
    signals = [sig(f"good{i}", 100, category=c, weight=30) for i, c in enumerate(trust.CATEGORY_WEIGHTS)]
    signals.append(sig("equivocation_free", 0, "critical", cap=5, weight=5))
    result = trust.compute(signals, 4)
    assert result["score"] == 5 and result["level"] == "critical"


def test_missing_and_stale_data_are_not_green():
    result = trust.compute([sig("a", None), sig("b", None), sig("c", 100, weight=1)], 3)
    assert result["status"] == "unclear" and result["basis"] in ("insufficient", "none")
    stale = trust.compute([sig("a", 100, observed_at="2020-01-01T00:00:00Z", max_age=60, weight=50),
                           sig("b", 100, weight=50)], 3)
    assert stale["counts"]["stale"] == 1 and stale["basis"] != "complete"


def test_too_few_independent_observers_cap_and_unclear():
    signals = [sig(f"s{i}", 100, category=c) for i, c in enumerate(trust.CATEGORY_WEIGHTS)]
    one = trust.compute(signals, 1)
    assert one["score"] == trust.OBSERVER_CAP and one["status"] == "assessed"
    none = trust.compute(signals, 0)
    assert none["status"] == "unclear" and none["level"] == "unclear"


def test_contradicting_observations_lower_agreement():
    result = trust.compute([sig("root_agreement", 50, "critical", weight=20), sig("other", 100)], 3)
    assert result["level"] == "warning" and result["score"] <= 100


def test_every_score_has_its_own_continuous_color_and_readable_contrast():
    hues = [trust.hue(score) for score in range(101)]
    assert hues[0] == 0 and hues[50] == 60 and hues[100] == 120
    assert all(b >= a for a, b in zip(hues, hues[1:]))
    assert len({trust.color(score)["accent"] for score in range(101)}) >= 100
    white = (1.0, 1.0, 1.0)
    for score in range(101):
        h = trust.hue(score)
        assert trust.contrast(trust.hsl_to_rgb(h, 90, 20), trust.hsl_to_rgb(h, 80, 95)) >= 4.5
        assert trust.contrast(trust.hsl_to_rgb(h, 75, 26), white) >= 4.5
        assert trust.contrast(trust.hsl_to_rgb(h, 75, 32), white) >= 3.0
        assert trust.contrast(trust.hsl_to_rgb(h, 85, 78), trust.hsl_to_rgb(h, 45, 13)) >= 4.5
        assert trust.contrast(trust.hsl_to_rgb(h, 75, 65), trust.hsl_to_rgb(h, 45, 13)) >= 4.5


def test_assessment_discloses_its_basis():
    result = trust.compute([sig("a", 80, observed_at="2026-10-09T00:00:00Z")], 2)
    assert {"signals", "completeness", "basis", "caps", "categories", "independent_observers"} <= set(result)
    assert result["signals"][0]["observed_at"] == "2026-10-09T00:00:00Z"


def test_unknown_baseline_is_unverifiable_not_a_mismatch():
    device = Signer.generate()
    keys, state = bound(device), actions.ActionState()
    params = {"set": {"a": "1"}}
    action = make_action(device, 1, actions.GENESIS, params)
    flags, info = actions.evaluate(keys, state, envelope(device, action))
    assert info["execution"] == "unverifiable" and [f.code for f in flags] == ["BASELINE_UNKNOWN"]

    second = make_action(device, 2, actions.action_hash(action), {"set": {"b": "new"}})
    flags, info = actions.evaluate(keys, state, envelope(device, second, actions.state_digest({"a": "1", "b": "new"})))
    assert info["execution"] == "unverifiable"


def test_claimed_baseline_must_be_consistent_with_the_signed_params():
    device = Signer.generate()
    keys, state = bound(device), actions.ActionState()
    action = make_action(device, 1, actions.GENESIS, {"set": {"a": "1"}})
    values = {"a": "2", "b": "x"}
    data = envelope(device, action, actions.state_digest(values))
    data["result"]["state_values"] = values
    flags, info = actions.evaluate(keys, state, data)
    assert info["execution"] == "mismatch" and flags[0].code == "RESULT_MISMATCH"

    ok_state = actions.ActionState()
    values = {"a": "1", "b": "x"}
    data = envelope(device, action, actions.state_digest(values))
    data["result"]["state_values"] = values
    flags, info = actions.evaluate(keys, ok_state, data)
    assert info["execution"] == "baseline-claimed" and ok_state.targets["users:profile"] == values
