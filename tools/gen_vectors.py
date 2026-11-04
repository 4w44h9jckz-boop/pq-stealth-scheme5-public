"""Emit the tier-2 conformance vectors. **Imports nothing from the implementation.**

    gen_vectors.py [--out vectors] [root]

Exit 0 if every row in every supported plan section is emitted, 1 on a coverage or content
failure, and 2 on a usage error.

WHY THIS FILE EXISTS AND WHAT IT MUST NOT DO. This generator comes ahead of any
cryptography, deliberately, for one reason: a fixture derived from the
code it validates tests self-consistency and nothing else. So it imports `tools/vecprim.py`
-- arithmetic written from the standards -- and the vendored NIST ACVP file, and nothing from
`crates/`.

**The row list is read off `vectors/PLAN.md`.** It is not written here. A generator with its own
list of ids can emit a set that disagrees with the plan and report success, and the plan is what
the author reads.

THE ML-KEM SUBSTITUTION, AND WHAT IT COSTS. The plan assumed the generator would use "one
ML-KEM library". None is installed and writing one is a project rather than a task -- 600-plus
lines of NTT and sampling, and a second unreviewed KEM in the tree. So this consumes NIST ACVP
`(d, z) -> ek` and `(ek, m) -> (c, k)` tuples instead, which is what the tier split already says.

ACVP's keyGen and encapsulation cases use different keys, so the surviving vectors use only
combinations directly supported by published tuples. The generator fails if the plan names a
row it cannot build; it never emits placeholders.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vecprim as vp  # noqa: E402

PLAN = Path("vectors/PLAN.md")
TIER1 = Path("vectors/tier1/ml-kem-768-acvp.json")

# The plan groups this generator builds, in emission order. Every invocation builds all of
# them: there is no partial run, which is what lets the manifest be REPLACED rather than
# merged below. `main` compares this set with the plan directly.
GROUPS = ("1", "2")

GROUP = re.compile(r"^## (?:\d+[a-z]?)\.\s*Section([\d.]+)")
ROW = re.compile(r"^\|\s*(V\d+-\d+[a-z]?)\s*\|")

# THE WITHDRAWN-ROW RULE: a row whose CLAIM cell is struck through or says "no vector --
# deliberately" is not a fixture. A reader should still see it, and a generator must neither
# emit it (that resurrects a requirement that no longer exists) nor report it missing (that
# demands a fixture for one). The self-test exercises both patterns.
#
# WITHDRAWN_CELL is case-sensitive and claim-cell-scoped on purpose: a live row's failure
# column may legitimately say "the withdrawn rule", and matching case-insensitively anywhere
# in the row read such a vector as withdrawn.
EMPTY_CELL = re.compile(r"no vector\s*[-—–]{1,2}\s*deliberately", re.I)
WITHDRAWN_CELL = re.compile(r"WITHDRAWN|~~")

# Inline code spans are blanked before the split, so a pipe inside backticks cannot shift
# every cell to its right -- the plan escapes literal pipes as `\|` inside code spans, and a
# raw split reads each one as a cell boundary.
CODE_SPAN = re.compile(r"`[^`]*`")


def claim_cell(line: str) -> str:
    """The second cell of a vector row, or "" if the row is malformed."""
    cells = CODE_SPAN.sub("", line).split("|")
    return cells[2].strip() if len(cells) > 2 else ""

# Read off Sections 2.4 and 2.5 rather than remembered: a remembered separator that appears
# nowhere in the specification would derive every V5 row under the wrong constant.
DS_CHANNEL = b"pq-stealth/pairwise/v1"
DS_PAYMENT = b"pq-stealth/pairwise-payment/v1"
COUNTER_BYTES = 16
# ERC-8441's schemeId 3 separator, used only by V5-06c to show the two schemes stay apart.
DS_HYBRID_ERC8441 = b"pq-stealth/hybrid-payment/v1"
# WHY A ROW IS `provisional`, in one place because it was in three and they drifted.
#
# The distinction that is easy to lose: "agreed" means two INDEPENDENT implementations
# converging in the wild — which is also how an unstated parameter masquerades as a
# chosen constant. What exists for these rows is this project's implementation plus
# a blinded re-derivation from this project's prose. Both are inside the project, so the
# constant is still a proposal -- and saying "no implementation has agreed" would send a
# reader looking for agreement that exists inside this project.
# The recipient of V5-14, V5-17 and V5-25, whose KEM key is an ACVP decapsulation case's. ACVP gives
# that key only expanded, with no (d, z) behind it, so it cannot be a Section 2.1 tracking key;
# the rows give ss_pq so that an implementation holding seeds can start there.
# Names NIST's file, not a local copy, so a row read on its own says where `dk` is.
ACVP_DK = "the expanded dk of NIST ACVP ML-KEM-encapDecap-FIPS203, decapsulation tcId {tc}"
RECIPIENT_EXPANDED = ("V5-09's viewing key with the KEM key of ACVP decapsulation tcId {tc}. "
                      "ACVP gives that key only in expanded form, so an implementation that "
                      "holds keys as (d, z) seeds starts from the ss_pq given here")
PROVISIONAL_WHY = ("NO OUTSIDE implementation has adopted it. This document's own implementation produces these bytes and an independent blinded re-derivation from the prose alone agreed on them, and neither is an outside party -- the constant is still a proposal")
def plan_rows(root: Path) -> dict[str, list[tuple[str, str]]]:
    """{group: [(row id, claim cell), ...]} read off the plan, in document order.

    The claim cell rides along so the caller can classify the row: a struck-through claim
    (WITHDRAWN, SUPERSEDED) or a "no vector -- deliberately" reservation is a row a reader
    should still see and a generator must neither emit nor report missing. Wave 1 never had
    one in its groups, which is why this function returned bare ids for as long as it did.
    """
    out: dict[str, list[tuple[str, str]]] = {}
    cur: str | None = None
    for ln in (root / PLAN).read_text(encoding="utf-8").split("\n"):
        m = GROUP.match(ln)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        m = ROW.match(ln)
        if m and cur:
            out[cur].append((m.group(1), claim_cell(ln)))
    return out


def repeated_ids(rows: dict[str, list[tuple[str, str]]]) -> list[str]:
    """Ids that appear more than once in the same plan section."""
    out: list[str] = []
    for group, items in rows.items():
        counts: dict[str, int] = {}
        for rid, _cell in items:
            counts[rid] = counts.get(rid, 0) + 1
        for rid, n in sorted(counts.items()):
            if n > 1:
                out.append(f"Section{group} {rid} ({n} times)")
    return out


def not_a_fixture(cell: str) -> bool:
    """Whether a plan row's claim cell marks it withdrawn or reserved."""
    return bool(EMPTY_CELL.search(cell) or WITHDRAWN_CELL.search(cell))


def tier1(root: Path) -> dict:
    return json.loads((root / TIER1).read_text(encoding="utf-8"))


def hx(b: bytes) -> str:
    return b.hex()


def resized(b: bytes, n: int) -> bytes:
    """`b` cut to `n` bytes, or padded to them with 0x11: how V5-15 makes its malformed fields."""
    return b[:n] + b"\x11" * (n - len(b))


# --------------------------------------------------------------------------------------
# Section1 -- common to every schemeId. No KEM, no curve beyond the group order.
# --------------------------------------------------------------------------------------

def group_1() -> dict[str, dict]:
    v: dict[str, dict] = {}
    ss = bytes(range(32))
    base, scalar = vp.h_of_ss(ss)
    v["V1-01"] = {
        "claim": "H(ss) = SHA256(DS_offset || ss), range-checked",
        "given": {"ss": hx(ss)},
        "expect": {"base": hx(base), "offset": f"{scalar:064x}"},
    }

    # V1-02 pins BIG-ENDIAN. The `wrong` column is the whole point: a little-endian read gives
    # a different scalar, a different address, and funds nobody can spend. So the vector states
    # the wrong answer too, computed the wrong way on purpose.
    be = vp.offset_scalar(base)
    le = int.from_bytes(base, "little") % vp.N
    v["V1-02"] = {
        "claim": "every digest is big-endian",
        "given": {"ss": hx(ss), "base": hx(base)},
        "expect": {"offset_big_endian": f"{be:064x}"},
        "wrong": {"offset_little_endian": f"{le:064x}",
                  "note": "a different scalar, therefore a different address, therefore funds "
                          "the recipient cannot spend. Silent and total"},
    }

    # V1-03 and V1-04 are the two ways out of range. Neither is reachable from a findable `ss`,
    # so `base` is supplied directly; the outcome is a failure, after which the sender draws
    # new randomness.
    zero = bytes(32)
    v["V1-03"] = {
        "claim": "the range check MUST reject base = 0",
        "given": {"base": hx(zero)},
        "expect": {"outcome": "fail"},
        "wrong": {"offset": f"{0:064x}",
                  "note": "no range check: offset 0 makes the stealth address the address of "
                          "spending_pk itself, which links the payment to the registered key"},
    }

    nb = vp.N.to_bytes(32, "big")
    v["V1-04"] = {
        "claim": "the range check MUST reject base = n",
        "given": {"base": hx(nb)},
        "expect": {"outcome": "fail"},
        "wrong": {"offset_reduced_mod_n": f"{vp.N % vp.N:064x}",
                  "note": "reducing mod n instead of failing, which some libraries do silently "
                          "and which gives offset 0"},
    }

    n1 = (vp.N - 1).to_bytes(32, "big")
    v["V1-05"] = {
        "claim": "base = n - 1 is valid",
        "given": {"base": hx(n1)},
        "expect": {"offset": f"{vp.offset_scalar(n1):064x}"},
        "wrong": {"note": "rejected -- an off-by-one in the bound loses a legitimate payment"},
    }

    tag = vp.view_tag(ss)
    v["V1-07"] = {
        "claim": "view_tag = SHA256(DS_viewtag || ss)[0]",
        "given": {"ss": hx(ss)},
        "expect": {"view_tag": hx(tag), "view_tag_bytes": vp.VIEW_TAG_BYTES},
        "wrong": {
            "superseded_eight_byte_width":
                hx(hashlib.sha256(vp.DS_VIEWTAG + ss).digest()[:8]),
            "trailing_byte_of_own_digest":
                hx(hashlib.sha256(vp.DS_VIEWTAG + ss).digest()[31:]),
            "leading_byte_of_H_ss": hx(base[:1]),
            "note": "an eight-byte tag is what a design that matches on the tag alone "
                    "needs; here the announced stealthAddress decides (Section 2.6) and the "
                    "tag is a one-byte prefilter, as ERC-5564 lays it out. An implementation "
                    "carrying the wider tag matches nothing",
        },
    }
    return v
def u128be(i: int) -> bytes:
    return i.to_bytes(COUNTER_BYTES, "big")


def channel_key(ss_ec: bytes, ss_pq: bytes, epk: bytes, ct: bytes, vpk: bytes, ek: bytes,
                ds: bytes = DS_CHANNEL) -> bytes:
    """Section 1.1's combiner under Section 2.4's separator."""
    return hashlib.sha3_256(ds + ss_ec + ss_pq + epk + ct + vpk + ek).digest()


def payment_secret(k: bytes, counter: int) -> bytes:
    """Section 2.5: SHA256(DS_payment || k_pairwise || u128be(counter))."""
    return hashlib.sha256(DS_PAYMENT + k + u128be(counter)).digest()


def payment(k: bytes, counter: int, spending_pt) -> tuple[bytes, bytes, bytes]:
    """(ss_i, view_tag, address) of the payment at `counter`."""
    ss_i = payment_secret(k, counter)
    stealth = vp.add(spending_pt, vp.mul(vp.h_of_ss(ss_i)[1]))
    return ss_i, vp.view_tag(ss_i), vp.address_of(stealth)


def window_outcomes(k: bytes, spending_pt, lookahead: int, counters: list[int],
                    lies: frozenset[int] = frozenset()) -> list[str]:
    """Section 2.6's window, run over memos at `counters`, written from the prose.

    A scanner keeps the highest matched counter h (0 after the first contact) and the counters
    it has matched in (h - L, h]. A memo matches at counter c >= 1 if h - L < c <= h + L, c is
    not matched, the view tag of ss_c equals metadata[0] and the address of ss_c equals
    stealthAddress.
    """
    high, matched = 0, {0}
    out = []
    for idx, c in enumerate(counters):
        _, tag, addr = payment(k, c, spending_pt)
        announced = addr if idx not in lies else bytes(20)
        hit = None
        for cand in range(max(1, high - lookahead + 1), high + lookahead + 1):
            if cand in matched:
                continue
            _, t2, a2 = payment(k, cand, spending_pt)
            if t2 == tag and a2 == announced:
                hit = cand
                break
        if hit is None:
            out.append("skip")
            continue
        matched.add(hit)
        high = max(high, hit)
        matched = {m for m in matched if m > high - lookahead}
        out.append(f"match at counter {hit}")
    return out


def group_2(t1: dict) -> dict[str, dict]:
    v: dict[str, dict] = {}
    en = t1["encapsulation"][0]
    ek = bytes.fromhex(en["ek"])
    ct = bytes.fromhex(en["c"])
    ss_pq = bytes.fromhex(en["k"])

    esk = int.from_bytes(bytes([0x22]) * 32, "big")
    epk_pt = vp.mul(esk)
    epk = vp.encode_compressed(epk_pt)
    v_seed = int.from_bytes(bytes([0x53]) * 32, "big")
    viewing_pk_ec = vp.encode_compressed(vp.mul(v_seed))

    # V5-04: ss_ec is the x-coordinate ALONE. The named wrong answers are the 65-byte point
    # and the 33-byte compressed form, so all three are emitted and they differ.
    shared_pt = vp.mul(esk, vp.decode_compressed(viewing_pk_ec))
    ss_ec = shared_pt[0].to_bytes(32, "big")

    # V5-09's recipient, built first so the rows before V5-09 can state their inputs in full:
    # spending 0x51.., viewing 0x53.., and the (d, z) of ACVP keygen tcId 27, so its ek is
    # NIST's. ERC-8441's vectors use spending 0x11.., viewing 0x33.. and tcId 26; schemeId 5
    # has its own keys (Section 2.1), and V5-26 checks the sender's side of that rule.
    spending_seed = bytes([0x51]) * 32
    kg = t1["keygen"][1]
    kem_seed = bytes.fromhex(kg["d"]) + bytes.fromhex(kg["z"])
    v_ec_seed = bytes([0x53]) * 32
    assert vp.encode_compressed(vp.mul(int.from_bytes(v_ec_seed, "big"))) == viewing_pk_ec
    delegated = v_ec_seed + kem_seed
    assert spending_seed not in (delegated[0:32], delegated[32:64], delegated[64:96]), \
        "Section2.1's component check would reject this fixture's own keygen seed"
    keygen_seed = spending_seed + delegated
    spending_pk = vp.encode_compressed(vp.mul(int.from_bytes(spending_seed, "big")))
    spending_pt = vp.decode_compressed(spending_pk)
    meta = spending_pk + viewing_pk_ec + bytes.fromhex(kg["ek"])

    v["V5-01"] = {"claim": "keygen seed is 128 B",
                  "given": {"lengths": [128, 96, 127],
                            "seeds": {"128": hx(keygen_seed), "96": hx(keygen_seed[:96]),
                                      "127": hx(keygen_seed[:127])},
                            "seeds_are": "V5-09's keygen seed, then its first 96 and its "
                                         "first 127 bytes"},
                  "expect": {"outcome": "outputs, then errors for 96 and 127"},
                  "wrong": {"note": "padding or truncating to 128 rather than rejecting; or "
                                    "accepting 96 bytes, which is a well-formed seed for a "
                                    "scheme with no EC half"}}
    components = {"viewing_ec_seed": 0, "d": 32, "z": 64}
    planted = {}
    for name, off in components.items():
        buf = bytearray(bytes([0x44]) * 96)
        buf[off:off + 32] = spending_seed
        planted[name] = hx(bytes(buf))
    v["V5-02"] = {"claim": "keygen MUST reject a seed whose spending_seed equals "
                           "viewing_ec_seed, d or z",
                  "given": {"spending_seed": hx(spending_seed),
                            "delegated_objects_by_component": planted},
                  "expect": {"outcome": "error, all three"},
                  "wrong": {"note": "comparing against viewing_ec_seed alone. That catches a "
                                    "port of ERC-5564's single-key meta-address and misses "
                                    "the same 32 bytes copied into the KEM seed, which a "
                                    "scanning service receives verbatim"}}
    clean = bytes([0x44]) * 96
    v["V5-02a"] = {"claim": "a keygen with no equal component is accepted",
                   "given": {"spending_seed": hx(spending_seed), "delegated": hx(clean)},
                   "expect": {"outcome": "outputs, no error"},
                   "wrong": {"note": "rejecting valid keygens -- the positive control, "
                                     "without which V5-02 passes on an implementation that "
                                     "rejects everything"}}
    v["V5-03"] = {"claim": "meta is 1250 B and both points are validated",
                  "given": {"spending_pk": hx(spending_pk),
                            "viewing_pk_ec_compact_0x05": hx(b"\x05" + viewing_pk_ec[1:]),
                            "meta_address": hx(spending_pk + b"\x05" + viewing_pk_ec[1:]
                                               + meta[66:]),
                            "meta_address_is": "V5-09's meta-address with viewing_pk_ec's tag "
                                               "set to 0x05"},
                  "expect": {"outcome": "error at decode"},
                  "wrong": {"note": "validating only spending_pk, which is the natural port "
                                    "of a decoder for a meta-address that carries one point"}}
    v["V5-04"] = {"claim": "ss_ec is the x-coordinate alone",
                  "given": {"esk": f"{esk:064x}", "viewing_pk_ec": hx(viewing_pk_ec)},
                  "expect": {"ss_ec": hx(ss_ec), "length": 32},
                  "wrong": {"uncompressed_65": hx(vp.encode_uncompressed(shared_pt)),
                            "compressed_33": hx(vp.encode_compressed(shared_pt)),
                            "note": "a different channel key, silently"}}

    ikm = ss_ec + ss_pq + epk + ct + viewing_pk_ec + ek
    k = hashlib.sha3_256(DS_CHANNEL + ikm).digest()
    v["V5-05"] = {"claim": "the domain separator is the FIRST input, neither appended nor "
                           "length-prefixed",
                  "provisional": True,
                  "provisional_because": PROVISIONAL_WHY,
                  "given": {"domain_separator": DS_CHANNEL.decode(), "ikm": hx(ikm)},
                  "expect": {"k_pairwise": hx(k)},
                  "wrong": {
                      "appended": hx(hashlib.sha3_256(ikm + DS_CHANNEL).digest()),
                      "length_prefixed": hx(hashlib.sha3_256(
                          bytes([len(DS_CHANNEL)]) + DS_CHANNEL + ikm).digest()),
                      "note": "a different channel key, silently, and with it every payment "
                              "on the channel",
                  }}
    three = ss_ec + ss_pq + epk
    v["V5-06"] = {"claim": "IKM is exactly ss_ec || ss_pq || epk || ct || viewing_pk_ec || ek",
                  "provisional": True,
                  "provisional_because": PROVISIONAL_WHY,
                  "given": {"parts": {"ss_ec": hx(ss_ec), "ss_pq": hx(ss_pq), "epk": hx(epk),
                                      "ct": hx(ct), "viewing_pk_ec": hx(viewing_pk_ec),
                                      "ek": hx(ek)},
                            "esk": f"{esk:064x}",
                            "acvp_encapsulation_tcId": en["tcId"],
                            "m": en["m"],
                            "parts_are": f"epk = esk*G and ss_ec = ECDH(esk, viewing_pk_ec).x "
                                         f"as in V5-04, viewing_pk_ec being V5-09's; ek, ct and "
                                         f"ss_pq are ACVP encapsulation tcId {en['tcId']}, "
                                         f"(ct, ss_pq) = ML-KEM.Encaps_internal(ek, m)"},
                  "expect": {"k_pairwise": hx(k)},
                  "wrong": {
                      "three_field_form": hx(hashlib.sha3_256(DS_CHANNEL + three).digest()),
                      "kem_only": hx(hashlib.sha3_256(b"pq-stealth/pairwise-pq/v1"
                                                      + ss_pq).digest()),
                      "note": "any other order, and any omission -> a different channel key. "
                              "The three-field form ss_ec || ss_pq || epk is the likeliest "
                              "omission, and SHA3-256(\"pq-stealth/pairwise-pq/v1\" || ss_pq) "
                              "is the KEM-only channel key of a scheme with no EC half",
                  }}
    ct2 = bytes.fromhex(t1["encapsulation"][1]["c"])
    v["V5-06a"] = {"claim": "ct is bound in",
                   "given": {"ct_a": hx(ct), "ct_b": hx(ct2),
                             "ct_b_is": f"the c of ACVP encapsulation tcId "
                                        f"{t1['encapsulation'][1]['tcId']}",
                             "everything_else": "V5-06's parts"},
                   "expect": {"k_a": hx(k),
                              "k_b": hx(channel_key(ss_ec, ss_pq, epk, ct2, viewing_pk_ec, ek)),
                              "assertion": "different"},
                   "wrong": {"note": "the same key. Hashing both ciphertexts in is what lets "
                                     "the combiner stay IND-CCA when only one component KEM "
                                     "is (Giacon-Heuer-Poettering, PKC 2018; the "
                                     "KeyCombineCCA_H of SP 800-227 Section 4.6.3)"}}
    vpk2 = vp.encode_compressed(vp.mul(int.from_bytes(bytes([0x55]) * 32, "big")))
    v["V5-06b"] = {"claim": "viewing_pk_ec is bound in",
                   "given": {"viewing_pk_ec_a": hx(viewing_pk_ec),
                             "viewing_pk_ec_b": hx(vpk2),
                             "viewing_ec_b": hx(bytes([0x55]) * 32),
                             "everything_else": "V5-06's parts"},
                   "expect": {"k_a": hx(k),
                              "k_b": hx(channel_key(ss_ec, ss_pq, epk, ct, vpk2, ek)),
                              "assertion": "different"},
                   "wrong": {"note": "the same key: nothing would bind the channel to the "
                                     "recipient's identity"}}

    # V5-06c: the same six inputs under ERC-8441's separator give ERC-8441's payment secret,
    # and the schemeId 3 announcement built from it is a skip under schemeId 5's rules.
    ss3 = channel_key(ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek, DS_HYBRID_ERC8441)
    tag3 = vp.view_tag(ss3)
    addr3 = vp.address_of(vp.add(spending_pt, vp.mul(vp.h_of_ss(ss3)[1])))
    _, tag5_0, addr5_0 = payment(k, 0, spending_pt)
    assert addr3 != addr5_0
    v["V5-06c"] = {"claim": "the channel key is not ERC-8441's payment secret, and an "
                            "ERC-8441 announcement is a skip under schemeId 5",
                   "given": {"everything_else": "V5-06's parts",
                             "erc8441_domain_separator": DS_HYBRID_ERC8441.decode(),
                             "erc8441_announcement": {"stealthAddress": hx(addr3),
                                                      "ephemeralPubKey": hx(epk + ct),
                                                      "metadata": hx(tag3)},
                             "announcement_is": "what ERC-8441's sender announces under "
                                                "schemeId 3 to V5-09's meta-address, with "
                                                "V5-06's epk and ct"},
                   "expect": {"k_pairwise": hx(k), "erc8441_ss": hx(ss3),
                              "assertion": "different",
                              "schemeId_5_view_tag_at_counter_0": hx(tag5_0),
                              "schemeId_5_address_at_counter_0": hx(addr5_0),
                              "outcome_under_schemeId_5": "skip, and no channel is retained"},
                   "wrong": {"note": "reusing \"pq-stealth/hybrid-payment/v1\" for the "
                                     "channel key, which makes a schemeId 3 payment secret "
                                     "and a channel key one value: the schemeId 3 announcement "
                                     "would open a channel"}}
    flipped = bytes([epk[0] ^ 0x01]) + epk[1:]
    v["V5-07"] = {"claim": "epk MUST be bound in",
                  "given": {"epk": hx(epk), "epk_parity_flipped": hx(flipped),
                            "everything_else": "V5-06's parts"},
                  "expect": {"k_a": hx(k),
                             "k_b": hx(channel_key(ss_ec, ss_pq, flipped, ct, viewing_pk_ec,
                                                   ek)),
                             "assertion": "different"},
                  "wrong": {"note": "the same key -- the flipped point has the same "
                                    "x-coordinate, so without epk in the IKM this is a "
                                    "replay with a different-looking first contact"}}
    ss_0, tag0, addr0 = payment(k, 0, spending_pt)
    v["V5-08"] = {"claim": "first contact wire shape",
                  "given": {"epk": hx(epk), "ct": hx(ct), "k_pairwise": hx(k),
                            "spending_pk": hx(spending_pk),
                            "inputs_are": "V5-06's epk, ct and channel key, and V5-09's "
                                          "spending_pk"},
                  "expect": {"stealthAddress": hx(addr0),
                             "ephemeralPubKey": hx(epk) + hx(ct),
                             "metadata": hx(tag0),
                             "ephemeralPubKey_bytes": len(epk) + len(ct),
                             "payload_bytes": len(epk) + len(ct) + len(tag0)},
                  "wrong": {"ct_then_epk": hx(ct) + hx(epk),
                            "ct_in_metadata": {"ephemeralPubKey": hx(epk),
                                               "metadata": hx(tag0) + hx(ct)},
                            "note": "ct || epk in ephemeralPubKey, which is the same length "
                                    "as the right answer, so no length check distinguishes "
                                    "it; and ct in metadata, which a conforming scanner skips "
                                    "on the ephemeralPubKey length"}}
    token_block = (bytes.fromhex("eeeeeeee") + bytes.fromhex("ee" * 20)
                   + (10**18).to_bytes(32, "big"))
    assert len(token_block) == 56 and token_block[-1] != tag0[0]
    v["V5-08a"] = {"claim": "the view tag is metadata[0], and any later bytes are ignored",
                   "given": {"ephemeralPubKey": hx(epk) + hx(ct),
                             "metadata_view_tag_only": hx(tag0),
                             "metadata_with_token_block": hx(tag0) + hx(token_block)},
                   "expect": {"view_tag_at_index_0": hx(tag0),
                              "outcome": "both metadata values parse, to the same view tag"},
                   "wrong": {"last_byte_of_metadata": hx(token_block[-1:]),
                             "note": "requiring metadata to be exactly one byte, which skips "
                                     "every payment from a sender that follows ERC-5564's "
                                     "token-metadata recommendation; or reading the tag off "
                                     "the end of metadata"}}

    v["V5-09"] = {"claim": "keygen MUST be deterministic in the seed -- the same 128 bytes "
                           "produce the same three outputs",
                  "given": {"keygen_seed": hx(keygen_seed),
                            "kem_seed_source": f"ML-KEM (d, z) of ACVP keygen tcId "
                                               f"{kg['tcId']}, so the ek below is NIST's "
                                               f"value and not this generator's"},
                  "expect": {"meta_address": hx(meta), "meta_address_bytes": len(meta),
                             "spending_pk": hx(spending_pk),
                             "viewing_pk_ec": hx(viewing_pk_ec),
                             "ek_at": "meta_address[66:1250]",
                             "tracking": hx(delegated), "tracking_bytes": len(delegated),
                             "master": hx(spending_seed)},
                  "wrong": {"note": "calling the KEM's randomness-taking keygen and ignoring "
                                    "kem_seed. The meta-address is still well formed and "
                                    "registration still succeeds, so nothing fails until the "
                                    "owner restores from the seed, gets a different dk, and "
                                    "can open no channel ever made to the registered ek"}}

    def with_half(at: int, half: bytes) -> bytes:
        seed = bytearray(keygen_seed)
        seed[at:at + 32] = half
        return bytes(seed)

    v["V5-10"] = {"claim": "spending_seed and viewing_ec_seed MUST each be a valid secp256k1 "
                           "scalar -- error at keygen",
                  "given": {"seeds": {
                      "spending_seed_0": hx(with_half(0, bytes(32))),
                      "spending_seed_n": hx(with_half(0, vp.N.to_bytes(32, "big"))),
                      "spending_seed_n_minus_1": hx(with_half(0, (vp.N - 1).to_bytes(32, "big"))),
                      "viewing_ec_seed_0": hx(with_half(32, bytes(32)))},
                      "seeds_are": "V5-09's keygen seed with the named 32-byte half replaced"},
                  "expect": {"outcome": "error, error, accepted, error"},
                  "wrong": {"note": "reducing the seed mod n instead of rejecting it: a "
                                    "library that reduces silently turns spending_seed = n "
                                    "into 0, and every payment to the resulting meta-address "
                                    "is spendable by anyone. n - 1 is the positive control"}}
    v["V5-11"] = {"claim": "decoding MUST reject a meta-address length other than 1250",
                  "given": {"lengths": [1249, 1250, 1251],
                            "meta_addresses": {"1249": hx(meta[:-1]), "1250": hx(meta),
                                               "1251": hx(meta + b"\x00")},
                            "meta_addresses_are": "V5-09's meta-address without its last "
                                                  "byte, as it is, and with 0x00 appended"},
                  "expect": {"outcome": "error, accepted, error"},
                  "wrong": {"note": "slicing [0:33], [33:66], [66:] with no length check"}}
    nonpoint_x = 5
    v["V5-12"] = {"claim": "33 bytes of the right length can still be a non-point -- both "
                           "points MUST be validated before the meta-address is used",
                  "given": {"viewing_pk_ec_nonpoint": hx(b"\x02" + nonpoint_x.to_bytes(32, "big")),
                            "why": f"x = {nonpoint_x} is the smallest positive x for which "
                                   f"x^3 + 7 is not a square mod p",
                            "viewing_pk_ec_valid": hx(viewing_pk_ec),
                            "meta_address_nonpoint": hx(
                                meta[:33] + b"\x02" + nonpoint_x.to_bytes(32, "big")
                                + meta[66:]),
                            "meta_address_valid": hx(meta),
                            "meta_addresses_are": "V5-09's meta-address with viewing_pk_ec "
                                                  "replaced by each"},
                  "expect": {"outcome": "error at decode, then accepted"},
                  "wrong": {"note": "checking the length and the 0x02/0x03 tag byte and "
                                    "storing the bytes; the ECDH that follows throws far from "
                                    "the meta-address that caused it"}}

    h0 = vp.h_of_ss(ss_0)[1]
    stealth_pt = vp.add(spending_pt, vp.mul(h0))
    assert vp.address_of(stealth_pt) == addr0
    uncompressed = vp.encode_uncompressed(stealth_pt)
    v["V5-13"] = {"claim": "address = keccak256(uncompressed(stealth_pk) without its 0x04 "
                           "prefix)[12..32]",
                  "given": {"stealth_pk_compressed": hx(vp.encode_compressed(stealth_pt)),
                            "stealth_pk_uncompressed": hx(uncompressed),
                            "stealth_pk_from": {"row": "V5-16",
                                                "spending_pk": hx(spending_pk),
                                                "ss_0": hx(ss_0)}},
                  "expect": {"address": hx(addr0), "eip55": vp.eip55(addr0)},
                  "wrong": {"keccak_of_compressed": hx(
                                vp.keccak256(vp.encode_compressed(stealth_pt))[12:32]),
                            "keccak_with_0x04_prefix": hx(vp.keccak256(uncompressed)[12:32]),
                            "first_20_bytes_not_last_20": hx(
                                vp.keccak256(uncompressed[1:])[0:20]),
                            "note": "each is 20 well-formed bytes and each is a different "
                                    "address nobody holds a key for"}}

    dc = next(c for c in t1["decapsulation"] if c["reason"] == "modified ciphertext")
    dk_88 = bytes.fromhex(dc["dk"])
    ek_88 = dk_88[1152:2336]
    assert hashlib.sha3_256(ek_88).digest() == dk_88[2336:2368], \
        "ek is not embedded in this dk where FIPS 203 puts it"
    ct_foreign = bytes.fromhex(dc["c"])
    ss_pq_88 = bytes.fromhex(dc["k"])
    k_88 = channel_key(ss_ec, ss_pq_88, epk, ct_foreign, viewing_pk_ec, ek_88)
    ss0_88, tag0_88, addr0_88 = payment(k_88, 0, spending_pt)
    announced_tag = bytes([tag0_88[0] ^ 0x01])
    v["V5-14"] = {"claim": "a view-tag mismatch at counter 0 is a skip, retains nothing -- "
                           "and decapsulation does not fail",
                  "given": {"acvp_decapsulation_tcId": dc["tcId"],
                            "acvp_reason": dc["reason"],
                            "dk": ACVP_DK.format(tc=dc["tcId"]),
                            "ek": hx(ek_88),
                            "ek_source": "dk[1152:2336] per FIPS 203's expanded key layout, "
                                         "checked against the H(ek) at dk[2336:2368]",
                            "viewing_ec": hx(v_ec_seed),
                            "viewing_pk_ec": hx(viewing_pk_ec),
                            "spending_pk": hx(spending_pk),
                            "recipient_is": RECIPIENT_EXPANDED.format(tc=dc["tcId"]),
                            "first_contact": {"stealthAddress": hx(addr0_88),
                                              "ephemeralPubKey": hx(epk + ct_foreign),
                                              "metadata": hx(announced_tag)}},
                  "expect": {"decapsulation": "returns 32 bytes and does NOT fail",
                             "ss_ec": hx(ss_ec),
                             "ss_pq": hx(ss_pq_88),
                             "k_pairwise": hx(k_88),
                             "ss_0": hx(ss0_88),
                             "derived_view_tag": hx(tag0_88),
                             "outcome": "skip, and no channel is retained",
                             "outcome_with_derived_view_tag":
                                 "match at counter 0, and the channel is retained"},
                  "wrong": {"note": "retaining a channel because decapsulation succeeded. It "
                                    "always does -- ML-KEM rejects implicitly, which is what "
                                    "this NIST case shows -- so such a scanner keeps one "
                                    "channel for every first contact anyone ever publishes. "
                                    "Raising on the mismatch is the other error: announce() is "
                                    "permissionless, so an error path there is a scanner "
                                    "denial of service (Section 2.9)"}}

    lengths = (0, 1, 33, 1120, 1121, 1122)
    v["V5-15"] = {"claim": "the ephemeralPubKey length selects first contact or memo, and "
                           "any other shape is a skip at the entry point, not an error",
                  "given": {"ephemeralPubKey_lengths": list(lengths),
                            "metadata_lengths": [0, 1, 57],
                            "ephemeralPubKeys": {str(n): hx(resized(epk + ct, n))
                                                 for n in lengths},
                            "metadatas": {str(n): hx(resized(tag0, n)) for n in (0, 1, 57)},
                            "fields_are": "V5-08's ephemeralPubKey and metadata, cut to each "
                                          "length or padded to it with 0x11 bytes"},
                  "expect": {"outcome": "skip if metadata is empty; otherwise 1121 bytes is "
                                        "a first contact, 0 bytes is a memo, and every other "
                                        "ephemeralPubKey length is a skip"},
                  "wrong": {"note": "raising, or propagating a library exception: anyone can "
                                    "call announce() with any bytes. Or treating a memo's "
                                    "empty ephemeralPubKey as malformed, which loses every "
                                    "payment after the first on every channel"}}

    spending_k = int.from_bytes(spending_seed, "big")
    stealth_sk = (spending_k + h0) % vp.N
    assert vp.mul(stealth_sk) == stealth_pt
    near_n = vp.N - 1
    near_sk = (near_n + h0) % vp.N
    near_pt = vp.add(vp.mul(near_n), vp.mul(h0))
    assert vp.mul(near_sk) == near_pt
    assert near_n + h0 >= vp.N, "the near-n case must actually need the reduction"
    v["V5-16"] = {"claim": "stealth_pk = spending_pk + H(ss_i)*G and stealth_sk = (spending_sk "
                           "+ H(ss_i)) mod n, and the two are one key pair",
                  "given": {"ss_0": hx(ss_0), "ss_0_from": "V5-21",
                            "spending_sk": hx(spending_seed),
                            "spending_pk": hx(spending_pk),
                            "spending_sk_near_n": f"{near_n:064x}"},
                  "expect": {"H_ss_0": f"{h0:064x}",
                             "stealth_pk": hx(vp.encode_compressed(stealth_pt)),
                             "stealth_sk": f"{stealth_sk:064x}",
                             "address": hx(addr0),
                             "near_n": {"stealth_pk": hx(vp.encode_compressed(near_pt)),
                                        "stealth_sk": f"{near_sk:064x}"}},
                  "wrong": {
                      "multiplicative_stealth_pk": hx(vp.encode_compressed(
                          vp.mul(h0, spending_pt))),
                      "k_pairwise_as_ss": hx(vp.encode_compressed(vp.add(
                          spending_pt, vp.mul(vp.h_of_ss(k)[1])))),
                      "near_n_reduced_mod_2_256": f"{(near_n + h0) % 2**256:064x}",
                      "note": "the tweak is additive, as in ERC-5564; hashing the channel key "
                              "itself instead of ss_0 gives one address for the whole channel; "
                              "and with spending_sk = n - 1 the sum passes n, so reducing it "
                              "mod 2^256 gives the key of a different address"}}

    dv = next(c for c in t1["decapsulation"] if c["reason"] == "valid decapsulation")
    dk_v = bytes.fromhex(dv["dk"])
    ek_v = dk_v[1152:2336]
    assert hashlib.sha3_256(ek_v).digest() == dk_v[2336:2368]
    ct_v = bytes.fromhex(dv["c"])
    ss_pq_v = bytes.fromhex(dv["k"])
    k_v = channel_key(ss_ec, ss_pq_v, epk, ct_v, viewing_pk_ec, ek_v)
    ss0_v, tag0_v, addr0_v = payment(k_v, 0, spending_pt)
    stealth_v = vp.add(spending_pt, vp.mul(vp.h_of_ss(ss0_v)[1]))
    lie = vp.keccak256(vp.encode_uncompressed(stealth_v))[12:32]
    assert lie != addr0_v
    v["V5-17"] = {"claim": "the announced stealthAddress decides: a first contact whose view "
                           "tag matches and whose address does not is a skip and retains "
                           "nothing",
                  "given": {"acvp_decapsulation_tcId": dv["tcId"],
                            "acvp_reason": dv["reason"],
                            "dk": ACVP_DK.format(tc=dv["tcId"]),
                            "ek": hx(ek_v),
                            "ek_source": "dk[1152:2336] per FIPS 203's expanded key layout, "
                                         "checked against the H(ek) at dk[2336:2368]",
                            "viewing_ec": hx(v_ec_seed),
                            "viewing_pk_ec": hx(viewing_pk_ec),
                            "spending_pk": hx(spending_pk),
                            "recipient_is": RECIPIENT_EXPANDED.format(tc=dv["tcId"]),
                            "first_contact": {"ephemeralPubKey": hx(epk + ct_v),
                                              "metadata": hx(tag0_v)},
                            "stealthAddress_honest": hx(addr0_v),
                            "stealthAddress_lie": hx(lie)},
                  "expect": {"ss_ec": hx(ss_ec), "ss_pq": hx(ss_pq_v), "k_pairwise": hx(k_v),
                             "ss_0": hx(ss0_v), "view_tag": hx(tag0_v),
                             "stealth_pk": hx(vp.encode_compressed(stealth_v)),
                             "address": hx(addr0_v),
                             "honest": "match at counter 0, and the channel is retained",
                             "lie": "skip, and no channel is retained"},
                  "wrong": {"note": "deciding on the one-byte view tag, which matches in both "
                                    "and lets 1 in 256 foreign first contacts through: such a "
                                    "scanner reports a payment at an address the announcement "
                                    "does not name, and retains a channel on it"}}

    bad_epks = {
        "tag_0x05_compact": b"\x05" + epk[1:],
        "tag_0x04": b"\x04" + epk[1:],
        "tag_0x00": b"\x00" + epk[1:],
        "x_not_on_curve": b"\x02" + nonpoint_x.to_bytes(32, "big"),
        "x_p_plus_1": b"\x02" + (vp.P + 1).to_bytes(32, "big"),
    }
    for name, b in bad_epks.items():
        try:
            vp.decode_compressed(b)
        except ValueError:
            continue
        raise AssertionError(f"V5-18's {name} decodes")
    vp.decode_compressed(b"\x02" + (1).to_bytes(32, "big"))
    v["V5-18"] = {"claim": "a 1121-byte ephemeralPubKey whose epk is not a valid compressed "
                           "point is a skip, not an error",
                  "given": {"ephemeralPubKeys": {name: hx(b + ct)
                                                 for name, b in bad_epks.items()},
                            "honest_ephemeralPubKey": hx(epk + ct),
                            "metadata": hx(tag0),
                            "fields_are": "each epk followed by V5-08's ct; metadata is "
                                          "V5-08's view tag"},
                  "expect": {"outcome": "skip for every ephemeralPubKeys entry; the honest "
                                        "one is processed"},
                  "wrong": {"note": "raising from the curve library, which the length check "
                                    "no longer stops; or accepting a non-canonical encoding -- "
                                    "canonicalising 0x05, or reducing x mod p, which reads "
                                    "x = p + 1 as the point with x = 1"}}

    checks = t1["encapsulation_key_check"]
    for c in checks:
        assert (vp.ek_out_of_range(bytes.fromhex(c["ek"])) is None) == c["testPassed"], \
            f"FIPS 203 Section 7.2 here disagrees with NIST on tcId {c['tcId']}"
    ek_bad_case = next(c for c in checks if not c["testPassed"])
    ek_good_case = next(c for c in checks if c["testPassed"])
    ek_bad = bytes.fromhex(ek_bad_case["ek"])
    bad_index, bad_value = vp.ek_out_of_range(ek_bad)
    v["V5-19"] = {"claim": "an ek that fails FIPS 203's encapsulation key check is an error, "
                           "and no first contact is made to it",
                  "given": {"acvp_encapsulationKeyCheck_tcId_invalid": ek_bad_case["tcId"],
                            "acvp_reason_invalid": ek_bad_case["reason"],
                            "acvp_encapsulationKeyCheck_tcId_valid": ek_good_case["tcId"],
                            "meta_address_invalid_ek": hx(spending_pk + viewing_pk_ec + ek_bad),
                            "meta_address_valid_ek": hx(spending_pk + viewing_pk_ec
                                                        + bytes.fromhex(ek_good_case["ek"])),
                            "meta_addresses_are": "V5-09's spending_pk and viewing_pk_ec, then "
                                                  "the ek of each ACVP case"},
                  "expect": {"first_coefficient_at_least_q": {"index": bad_index,
                                                              "value": bad_value,
                                                              "q": vp.ML_KEM_Q},
                             "outcome": "the invalid one is an error, at decode or at "
                                        "encapsulation, and no first contact is made; the "
                                        "valid one encapsulates"},
                  "wrong": {"note": "encapsulating anyway: a library that reduces each "
                                    "coefficient mod q encapsulates to a key other than the "
                                    "registered one, and the channel opens to nobody"}}

    # ----------------------------------------------------------------------------------
    # V5-20..V5-25 -- the channel: payment secrets, counter 0, memos, the window, replays.
    # ----------------------------------------------------------------------------------
    big = 2**64
    secrets = {str(i): hx(payment_secret(k, i)) for i in (0, 1, 2, big)}
    v["V5-20"] = {"claim": "ss_i = SHA256(\"pq-stealth/pairwise-payment/v1\" || k_pairwise || "
                           "u128be(i)), the counter 16 bytes big-endian",
                  "given": {"k_pairwise": hx(k), "k_pairwise_from": "V5-06",
                            "counters": [str(i) for i in (0, 1, 2, big)],
                            "counters_are": "decimal strings, because 2^64 is past the "
                                            "integers most JSON parsers read exactly"},
                  "expect": {"ss_by_counter": secrets,
                             "view_tag_by_counter": {i: hx(vp.view_tag(bytes.fromhex(s)))
                                                     for i, s in secrets.items()}},
                  "wrong": {
                      "counter_8_bytes": hx(hashlib.sha256(
                          DS_PAYMENT + k + (1).to_bytes(8, "big")).digest()),
                      "counter_little_endian": hx(hashlib.sha256(
                          DS_PAYMENT + k + (1).to_bytes(16, "little")).digest()),
                      "separator_appended": hx(hashlib.sha256(
                          k + u128be(1) + DS_PAYMENT).digest()),
                      "note": "each for counter 1, and each a different payment secret: the "
                              "counter is never published, so sender and scanner must encode "
                              "it the same way or every memo is lost. Counter 2^64 does not "
                              "fit in 8 bytes"}}
    v["V5-21"] = {"claim": "the first contact is the payment at counter 0: its view tag and "
                           "stealthAddress are those of ss_0",
                  "given": {"k_pairwise": hx(k), "spending_pk": hx(spending_pk),
                            "inputs_are": "V5-06's channel key and V5-09's spending_pk"},
                  "expect": {"ss_0": hx(ss_0), "view_tag": hx(tag0),
                             "stealthAddress": hx(addr0)},
                  "wrong": {"view_tag_of_k_pairwise": hx(vp.view_tag(k)),
                            "address_of_k_pairwise": hx(vp.address_of(vp.add(
                                spending_pt, vp.mul(vp.h_of_ss(k)[1])))),
                            "address_at_counter_1": hx(payment(k, 1, spending_pt)[2]),
                            "note": "deriving the first payment from the channel key itself, "
                                    "or starting the counter at 1. A scanner that admits the "
                                    "channel and derives no payment at counter 0 loses the "
                                    "first payment on every channel"}}
    memos = []
    for i in (1, 2, 3):
        _, t, a = payment(k, i, spending_pt)
        memos.append({"counter": i, "stealthAddress": hx(a), "ephemeralPubKey": "",
                      "metadata": hx(t)})
    v["V5-22"] = {"claim": "a memo is stealthAddress, an empty ephemeralPubKey and the view "
                           "tag, and memos start at counter 1",
                  "given": {"k_pairwise": hx(k), "spending_pk": hx(spending_pk),
                            "inputs_are": "V5-06's channel key and V5-09's spending_pk"},
                  "expect": {"memos": memos, "payload_bytes": 1},
                  "wrong": {"memo_at_counter_0": {"stealthAddress": hx(addr0),
                                                  "metadata": hx(tag0)},
                            "counter_on_the_wire": hx(tag0) + hx(u128be(1)),
                            "note": "starting memos at counter 0, which re-derives the first "
                                    "contact's address and merges two payments onto one key; "
                                    "or publishing the counter, which tells every observer each "
                                    "payment's index and a channel's age"}}

    lookahead = 20
    seq = [21, 20, 1, 1, 21, 41, 2, 22]
    window_memos = []
    for c in seq:
        _, t, a = payment(k, c, spending_pt)
        window_memos.append({"stealthAddress": hx(a), "metadata": hx(t),
                             "sent_at_counter": c})
    outcomes = window_outcomes(k, spending_pt, lookahead, seq)
    assert outcomes == ["skip", "match at counter 20", "match at counter 1", "skip",
                        "match at counter 21", "match at counter 41", "skip",
                        "match at counter 22"], outcomes
    v["V5-23"] = {"claim": "the window: a memo is tried at every unmatched counter c >= 1 with "
                           "h - SCAN_LOOKAHEAD < c <= h + SCAN_LOOKAHEAD, h the highest "
                           "counter matched",
                  "given": {"k_pairwise": hx(k), "spending_pk": hx(spending_pk),
                            "SCAN_LOOKAHEAD": lookahead,
                            "state": "the channel just admitted from V5-21's first contact: "
                                     "h = 0, counter 0 matched",
                            "memos_in_order": window_memos},
                  "expect": {"outcomes": outcomes,
                             "why": ["21 > 0 + 20", "first memo inside the window",
                                     "out of order, inside the band below h = 20",
                                     "a replay of a matched counter",
                                     "inside the window above h = 20",
                                     "inside the window above h = 21",
                                     "2 <= 41 - 20, below the band",
                                     "22 > 41 - 20, inside the band"]},
                  "wrong": {"note": "trying only counters above h, which loses every memo "
                                    "included out of order; trying every counter below h, "
                                    "which makes the window unbounded; or matching a replayed "
                                    "memo again, which reports one payment twice"}}
    _, tag1, addr1 = payment(k, 1, spending_pt)
    stealth1 = vp.add(spending_pt, vp.mul(vp.h_of_ss(payment_secret(k, 1))[1]))
    lie1 = vp.keccak256(vp.encode_uncompressed(stealth1))[12:32]
    v["V5-24"] = {"claim": "the announced stealthAddress decides a memo: the right view tag "
                           "with another address is a skip",
                  "given": {"k_pairwise": hx(k), "spending_pk": hx(spending_pk),
                            "state": "as V5-23, h = 0",
                            "memo_honest": {"stealthAddress": hx(addr1), "metadata": hx(tag1)},
                            "memo_lie": {"stealthAddress": hx(lie1), "metadata": hx(tag1)}},
                  "expect": {"honest": "match at counter 1", "lie": "skip, and h stays 0"},
                  "wrong": {"note": "matching memos on the one-byte view tag, which a memo "
                                    "for someone else carries with probability 1/256 per "
                                    "counter tried: a scanner with 100 channels and a window "
                                    "of 40 counters would match most foreign memos"}}
    _, tag1_v, addr1_v = payment(k_v, 1, spending_pt)
    v["V5-25"] = {"claim": "a replayed first contact retains one channel and reports no "
                           "second payment",
                  "given": {"first_contact": {"stealthAddress": hx(addr0_v),
                                              "ephemeralPubKey": hx(epk + ct_v),
                                              "metadata": hx(tag0_v)},
                            "memo_at_counter_1": {"stealthAddress": hx(addr1_v),
                                                  "ephemeralPubKey": "",
                                                  "metadata": hx(tag1_v)},
                            "recipient_is": "V5-17's",
                            "received_in_order": ["first_contact", "memo_at_counter_1",
                                                  "first_contact"]},
                  "expect": {"k_pairwise": hx(k_v),
                             "outcomes": ["match at counter 0, channel retained",
                                          "match at counter 1",
                                          "skip: the channel is already retained"],
                             "channels_retained": 1, "highest_counter": 1},
                  "wrong": {"note": "retaining the channel again, which grows the list "
                                    "without bound or rewinds h and re-reports old memos; or "
                                    "reporting counter 0 again, which shows one payment twice"}}

    # V5-26: a sender refuses to pay under schemeId 5 when another registry entry of the
    # recipient contains one of its schemeId 5 keys. ERC-8441's own vector recipient (V3-09:
    # spending 0x11.., viewing 0x33.., ACVP keygen tcId 26) is one of the unrelated entries.
    def point(byte: int) -> bytes:
        return vp.encode_compressed(vp.mul(int.from_bytes(bytes([byte]) * 32, "big")))

    kg3 = t1["keygen"][0]
    erc8441_meta = point(0x11) + point(0x33) + bytes.fromhex(kg3["ek"])
    other_spending, other_viewing = point(0x61), point(0x63)
    own_ek = meta[66:]
    entries = {
        "schemeId_3_same_meta_address": meta,
        "schemeId_3_same_ek_other_points": other_spending + other_viewing + own_ek,
        "schemeId_1_same_spending_pk": spending_pk + other_viewing,
        "schemeId_1_same_viewing_pk_ec": other_spending + viewing_pk_ec,
        "schemeId_1_unrelated": other_spending + other_viewing,
        "schemeId_3_erc8441_vector_recipient": erc8441_meta,
        "empty": b"",
    }

    def shares(entry: bytes) -> bool:
        return any(key in entry for key in (spending_pk, viewing_pk_ec, own_ek))

    outcomes = {name: "do not pay under schemeId 5" if shares(e) else "pay"
                for name, e in entries.items()}
    assert list(outcomes.values()).count("pay") == 3
    v["V5-26"] = {"claim": "a sender MUST NOT pay under schemeId 5 when another registry entry "
                           "of the recipient contains its spending_pk, viewing_pk_ec or ek",
                  "given": {"schemeId_5_meta_address": hx(meta),
                            "schemeId_5_meta_address_is": "V5-09's",
                            "other_entries": {name: hx(e) for name, e in entries.items()},
                            "other_entries_are": "the recipient's entry under another "
                                                 "schemeId: ERC-8441 meta-addresses for "
                                                 "schemeId 3, ERC-5564's spending_pk || "
                                                 "viewing_pk for schemeId 1; points 0x61.. "
                                                 "and 0x63.. are unrelated keys"},
                  "expect": {"outcomes": outcomes},
                  "wrong": {"note": "checking only an identical meta-address, which misses one "
                                    "key reused inside another encoding; or checking only "
                                    "schemeId 3, which misses keys reused under schemeId 1"}}
    return v


BUILDERS = {"1": lambda t1: group_1(), "2": group_2}


def canonical(row) -> str:
    """A row's canonical text, for comparing a fresh generation against a committed file.

    A FULL ROUND TRIP, not just a dump. `sort_keys` orders INTEGER keys numerically and the same
    keys, once parsed from JSON, are strings ordered lexicographically -- so `{0: .., 5: ..,
    16: ..}` dumps as 0, 5, 16 and its own parsed form dumps as 0, 16, 5. An offset map with
    integer keys, and that alone reported it stale against a byte-identical file: a false positive
    in a staleness gate, which is the kind that teaches a reader to ignore it. Tuples are the same
    story in a different key -- a builder returning one dumps an array and reads back a list.

    **Hoisted out of `main`** so it can be tested directly. As a closure the only way to
    reach it is through the CLI, and a mutation removing the round trip would then survive
    the whole suite: nothing in the tree *emits* an integer key or a tuple by a path the
    self-test exercises, so the guard could not be shown to do anything. A guard that cannot
    be made to fail is a comment.
    """
    return json.dumps(json.loads(json.dumps(row)), sort_keys=True)


def main(argv: list[str]) -> int:
    args = argv[1:]
    out_dir = "vectors"
    # `--check` regenerates into memory and compares against what is committed, writing
    # nothing. A gate that
    # needs write access is a gate an independent reviewer cannot run.
    check_only = "--check" in args
    if check_only:
        args.remove("--check")
    if "--out" in args:
        k = args.index("--out")
        if k + 1 >= len(args):
            print("usage error: --out needs a value", file=sys.stderr)
            return 2
        out_dir = args[k + 1]
        del args[k:k + 2]
    bad = [a for a in args if a.startswith("-")]
    if bad or len(args) > 1:
        print(f"usage error: unexpected argument(s) {bad or args[1:]}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(args[0] if args else ".").resolve()
    if not (root / PLAN).is_file():
        print(f"usage error: no plan at {root / PLAN}", file=sys.stderr)
        return 2
    if not (root / TIER1).is_file():
        print(f"usage error: no vendored ACVP file at {root / TIER1}. Tier 1 is NIST's and "
              f"this generator does not compute it.", file=sys.stderr)
        return 2

    rows = plan_rows(root)
    plan_groups = set(rows)
    supported_groups = set(GROUPS)
    if plan_groups != supported_groups:
        missing_groups = sorted(supported_groups - plan_groups)
        unsupported_groups = sorted(plan_groups - supported_groups)
        if missing_groups:
            print(f"FAIL: plan is missing supported section(s): "
                  f"{', '.join("Section" + group for group in missing_groups)}",
                  file=sys.stderr)
        if unsupported_groups:
            print(f"FAIL: plan contains unsupported section(s): "
                  f"{', '.join("Section" + group for group in unsupported_groups)}",
                  file=sys.stderr)
        return 1
    repeated = repeated_ids(rows)
    if repeated:
        print("FAIL: PLAN lists the same id more than once in a section:", file=sys.stderr)
        for line in repeated:
            print(f"  {line}", file=sys.stderr)
        return 1
    t1 = tier1(root)

    # The ML-KEM library's acceptance test, run on EVERY invocation rather than once by hand.
    # It is not trusted because it is popular; it is trusted for exactly the NIST tuples it
    # reproduces, and a disagreement is a hard failure because every KEM-bearing row below
    # would otherwise be built on it silently. The shipped rows use vendored ACVP values, so
    # an absent optional implementation does not reduce generator coverage.
    if vp.have_kem():
        disagreements = vp.acvp_selftest(t1)
        checks = (len(t1.get("keygen", []))
                  + 2 * len(t1.get("encapsulation", []))
                  + len(t1.get("decapsulation", [])))
        rejections = sum(1 for c in t1.get("decapsulation", [])
                         if c.get("reason") == "modified ciphertext")
        print(f"ML-KEM: kyber-py, acceptance test against the vendored NIST ACVP file -- "
              f"{checks - len(disagreements)} matched, {len(disagreements)} differed "
              f"({rejections} of them IMPLICIT-REJECTION cases)")
        # A count of zero rejection cases means the file lost them, and the oracle would then
        # be silently weakened: strong on keygen and encapsulation, blind on the
        # path V5-14 is emitted through.
        if rejections == 0:
            print("\nFAIL: the vendored ACVP file carries no `modified ciphertext` "
                  "decapsulation case, so implicit rejection -- the property Section 2.6's "
                  "admission rule rests on -- has no external witness.",
                  file=sys.stderr)
            return 1
        if disagreements:
            for d in disagreements:
                print(f"  {d}", file=sys.stderr)
            print("\nFAIL: the ML-KEM implementation disagrees with NIST. Every row below "
                  "would be built on it.", file=sys.stderr)
            return 1
    else:
        print("ML-KEM: absent (kyber-py not installed) -- optional ACVP implementation "
              "cross-check not run; all rows still build from vendored NIST values")

    dest = root / out_dir
    dest.mkdir(parents=True, exist_ok=True)

    emitted = 0
    manifest: dict[str, dict] = {}
    missing: list[str] = []
    skipped_rows: list[str] = []
    stale: list[str] = []
    print(f"groups: {', '.join("Section" + g for g in GROUPS)}")
    for g in GROUPS:
        want = rows.get(g)
        if want is None:
            print(f"  Section{g}: the plan has no group for it", file=sys.stderr)
            return 1
        built = BUILDERS[g](t1) if g in BUILDERS else {}
        # `slots` are the rows that are fixtures. Reporting a withdrawn or reserved row as
        # missing would demand a fixture for a requirement that no longer exists; emitting
        # one would resurrect it.
        slots = [rid for rid, cell in want if not not_a_fixture(cell)]
        skipped_rows.extend(f"Section{g} {rid}" for rid, cell in want if not_a_fixture(cell))
        body: dict[str, dict] = {}
        for rid in slots:
            if rid in built:
                body[rid] = built[rid]
                emitted += 1
            else:
                missing.append(f"Section{g} {rid}")
        # The plan is the authority on the row set, so a slot the plan lists and this file does
        # not build is a FINDING rather than a silent omission -- which is the whole reason the
        # ids are read off the plan instead of written here.
        f = dest / f"section-{g.replace('.', '_')}.json"
        blob = (json.dumps({"section": f"Section{g}", "vectors": body},
                           indent=2) + "\n").encode("utf-8")
        if check_only:
            if not f.is_file():
                stale.append(f"{f.name}: absent")
                print(f"  Section{g}: {f.name} ABSENT")
                continue
            try:
                committed_file = json.loads(f.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                stale.append(f"{f.name}: not valid JSON ({e})")
                print(f"  Section{g}: {f.name} UNREADABLE")
                continue
            if not isinstance(committed_file, dict):
                stale.append(f"{f.name}: top level is not an object")
                print(f"  Section{g}: {f.name} UNREADABLE")
                continue
            committed = committed_file.get("vectors", {})
            if not isinstance(committed, dict):
                committed = {}
            # Compared through `json.dumps`, NOT as Python objects. A tuple in a row
            # serialises to a JSON array and parses back as a list, so `dict != dict` on a
            # freshly built row against a parsed one reports a difference that does not
            # exist in the file — a row reads as stale in a tree whose committed file is
            # byte-identical to a fresh generation. A false positive in a staleness gate
            # is the kind that teaches a reader to ignore it.
            norm = canonical

            diff = 0
            want_section = f"Section{g}"
            got_section = committed_file.get("section")
            if got_section != want_section:
                stale.append(
                    f"{f.name}: section is {got_section!r}, expected {want_section!r}"
                )
                diff += 1
            for rid, fresh_row in body.items():
                if rid not in committed:
                    stale.append(f"{f.name}: {rid} is missing from the committed file")
                    diff += 1
                elif norm(committed[rid]) != norm(fresh_row):
                    stale.append(f"{f.name}: {rid} differs from a fresh generation")
                    diff += 1
            for rid in committed:
                if rid not in body:
                    stale.append(f"{f.name}: {rid} is committed and the plan no longer lists "
                                 f"it as a fixture -- deleted, withdrawn or "
                                 f"reserved")
                    diff += 1
            state = "STALE" if diff else "current"
            print(f"  Section{g}: {len(body)}/{len(slots)} slot(s), {f.name} {state}")
        else:
            f.write_bytes(blob)
            print(f"  Section{g}: {len(body)}/{len(slots)} slot(s) written to {f.name}")
        entry = {"sha256": hashlib.sha256(blob).hexdigest(),
                 "rows_in_plan": len(want), "rows_present": len(body)}
        # Only stated when nonzero, so a group with no such rows keeps its exact committed
        # bytes.
        if len(want) != len(slots):
            entry["rows_withdrawn_or_reserved"] = len(want) - len(slots)
        manifest[f.name] = entry

    # THE MANIFEST IS REPLACED, NOT MERGED, and that is a change from when this generator
    # ran one wave at a time. Then, a run rebuilt part of the set and had to carry the rest
    # of the committed manifest over or it would name fewer files than ship. Now every run
    # builds every group, so a carried-over entry can only be one thing: a file that has
    # stopped shipping, still named. That is not hypothetical -- entries for two files from
    # an earlier layout outlived both files, and `--check` passed anyway, because it verifies
    # the files that are present rather than the names that are listed.
    # Sorted by file name so the byte order does not depend on iteration order.
    mf = dest / "manifest.json"
    merged: dict[str, dict] = dict(manifest)
    # The runner is named CONDITIONALLY, because this manifest ships into trees that do not
    # carry one: a single-scheme export drops the conformance crate, and a `_what` naming it
    # unconditionally would point a reader at a package their tree does not contain. What is
    # true in every tree is the generator's own `--check`.
    man = (json.dumps({"_what": "sha256 per emitted file. the conformance runner verifies "
                                "these where a tree carries one, and `gen_vectors.py --check` "
                                "re-derives every rebuildable row from the specification "
                                "either way -- fixture/manifest CONSISTENCY, not adversarial "
                                "integrity: this manifest lives in the same tree as the "
                                "fixtures, so an editor who changes a fixture can rehash it "
                                "here in the same commit. What it catches is the accidental "
                                "or incomplete edit. Protection against deliberate oracle "
                                "replacement comes from provenance -- the committed "
                                "generator, the blinded re-derivation, the NIST-oracled "
                                "rows.",
                       "tier1_source": t1["sources"],
                       "files": dict(sorted(merged.items()))}, indent=2)
           + "\n").encode("utf-8")
    if check_only:
        if not mf.is_file():
            stale.append("manifest.json: absent")
        elif mf.read_bytes() != man:
            stale.append("manifest.json: differs from a fresh generation")
    else:
        mf.write_bytes(man)

    print(f"\n{emitted} vector(s) emitted")
    if skipped_rows:
        # Named, not just counted: a silently narrowed row set reads as full coverage.
        print(f"{len(skipped_rows)} plan row(s) withdrawn or reserved, not a generator's to "
              f"emit: {', '.join(skipped_rows)}")
    if missing:
        print(f"\nFAIL: {len(missing)} row(s) in the plan that this generator does not build, "
              f"and silence about a row the author will look for is the one outcome worse than "
              f"an absent vector:")
        for m in missing:
            print(f"  {m}")
        return 1
    if stale:
        print(f"\nFAIL: {len(stale)} committed row(s) or file(s) are not what the generator "
              f"produces:")
        for t in stale:
            print(f"  {t}")
        print(f"\nRegenerate with `python3 tools/gen_vectors.py` and commit the "
              "result.")
        return 1
    print("OK: every supported plan row was emitted"
          + (", and every committed file matches a fresh generation" if check_only else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
