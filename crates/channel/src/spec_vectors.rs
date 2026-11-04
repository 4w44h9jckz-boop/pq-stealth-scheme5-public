//! Spec vectors from `vectors/section-*.json`.
//!
//! Expected bytes come from the committed fixtures, which `tools/gen_vectors.py` builds without
//! this crate. The module sits under `src/` so it can reach the crate-private seams the
//! expanded-key rows need (they start from a given `ss_pq`).

use super::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const SECTION_1: &str = include_str!("../../../vectors/section-1.json");
const SECTION_2: &str = include_str!("../../../vectors/section-2.json");
const ACVP: &str = include_str!("../../../vectors/tier1/ml-kem-768-acvp.json");

// V1-06 is withdrawn: §1 does not retry with a counter.
const SECTION_1_CASES: &[&str] = &["V1-01", "V1-02", "V1-03", "V1-04", "V1-05", "V1-07"];
const SECTION_2_CASES: &[&str] = &[
    "V5-01", "V5-02", "V5-02a", "V5-03", "V5-04", "V5-05", "V5-06", "V5-06a", "V5-06b", "V5-06c",
    "V5-07", "V5-08", "V5-08a", "V5-09", "V5-10", "V5-11", "V5-12", "V5-13", "V5-14", "V5-15",
    "V5-16", "V5-17", "V5-18", "V5-19", "V5-20", "V5-21", "V5-22", "V5-23", "V5-24", "V5-25",
    "V5-26",
];

fn parse(raw: &str) -> Value {
    serde_json::from_slice(raw.as_bytes()).expect("committed fixture is JSON")
}

fn section_1() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(SECTION_1))
}

fn section_2() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(SECTION_2))
}

fn acvp() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(ACVP))
}

fn acvp_case(section: &str, tc_id: u64) -> &'static Value {
    obj(acvp(), section)
        .as_array()
        .unwrap_or_else(|| panic!("ACVP {section} is an array"))
        .iter()
        .find(|case| u64_field(case, "tcId") == tc_id)
        .unwrap_or_else(|| panic!("no ACVP {section} case has tcId {tc_id}"))
}

/// `ek` out of an ACVP decapsulation case's 2 400-byte expanded `dk`: FIPS 203 puts it at
/// `dk[1152..2336]`, followed by `H(ek)`.
fn acvp_ek_of_expanded_dk(case: &Value) -> Vec<u8> {
    let dk = hx(case, "dk");
    assert_eq!(dk.len(), 2400, "expanded dk");
    let ek = &dk[1152..2336];
    assert_eq!(Sha3_256::digest(ek).as_slice(), &dk[2336..2368], "H(ek)");
    ek.to_vec()
}

fn row<'a>(doc: &'a Value, id: &str) -> &'a Value {
    doc.get("vectors")
        .and_then(|v| v.get(id))
        .unwrap_or_else(|| panic!("fixture missing {id}"))
}

fn obj<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    obj(v, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn u64_field(v: &Value, key: &str) -> u64 {
    obj(v, key)
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a u64"))
}

fn u64_array(v: &Value, key: &str) -> Vec<u64> {
    obj(v, key)
        .as_array()
        .unwrap_or_else(|| panic!("{key} is not an array"))
        .iter()
        .map(|x| x.as_u64().expect("u64"))
        .collect()
}

fn str_array<'a>(v: &'a Value, key: &str) -> Vec<&'a str> {
    obj(v, key)
        .as_array()
        .unwrap_or_else(|| panic!("{key} is not an array"))
        .iter()
        .map(|x| x.as_str().expect("string"))
        .collect()
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn address(v: &Value, key: &str) -> [u8; 20] {
    hx(v, key)
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{key} is {} bytes, not 20", b.len()))
}

fn b32(v: &Value, key: &str) -> Bytes32 {
    hx(v, key)
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{key} is {} bytes, not 32", b.len()))
}

fn point(bytes: &[u8]) -> CompressedPoint {
    pqsa_ec::decode_point(bytes).expect("fixture point is SEC1 compressed")
}

fn encode<T: AsRef<[u8]> + ?Sized>(bytes: &T) -> String {
    hex::encode(bytes.as_ref())
}

fn resized(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.resize(len, 0x11);
    out
}

fn v5_09() -> &'static Value {
    obj(row(section_2(), "V5-09"), "expect")
}

fn v5_09_seed() -> Vec<u8> {
    hx(obj(row(section_2(), "V5-09"), "given"), "keygen_seed")
}

fn v5_09_point(key: &str) -> CompressedPoint {
    point(&hx(v5_09(), key))
}

/// `checkStealthAddress` (§2.10) with V5-09's keys.
fn v5_09_check(stealth_address: &[u8; 20], ephemeral_pub_key: &[u8]) -> Result<bool, Error> {
    erc5564::check_stealth_address(
        stealth_address,
        ephemeral_pub_key,
        &hx(v5_09(), "tracking"),
        &hx(v5_09(), "spending_pk"),
    )
}

fn channel_key_of(parts: &Value) -> Zeroizing<Bytes32> {
    channel_key(
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(parts, "epk")),
        &hx(parts, "ct"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .expect("V5-06 parts have the right lengths")
}

fn v5_06_parts() -> &'static Value {
    obj(obj(row(section_2(), "V5-06"), "given"), "parts")
}

/// A book holding V5-06's channel, just admitted: `h = 0`.
fn v5_06_book() -> (ScannerChannels, Zeroizing<Bytes32>) {
    let k = channel_key_of(v5_06_parts());
    let mut book = ScannerChannels::default();
    assert!(book.retain(&k, v5_09_point("spending_pk")));
    (book, k)
}

fn memo(v: &Value) -> Memo {
    let (addr, metadata) = (address(v, "stealthAddress"), hx(v, "metadata"));
    match Announcement::from_bytes(&addr, &[], &metadata).expect("a memo") {
        Announcement::Memo(m) => m,
        Announcement::FirstContact(_) => panic!("not a memo"),
    }
}

fn first_contact(v: &Value, addr: &[u8; 20]) -> FirstContact {
    match Announcement::from_bytes(addr, &hx(v, "ephemeralPubKey"), &hx(v, "metadata"))
        .expect("a first contact")
    {
        Announcement::FirstContact(fc) => fc,
        Announcement::Memo(_) => panic!("not a first contact"),
    }
}

/// The channel key for an expanded-key recipient row: the ECDH half from V5-09's viewing key,
/// the KEM half from the row's given `ss_pq`, which is NIST's.
fn expanded_recipient_key(
    given: &Value,
    expect: &Value,
    fc: &FirstContact,
    nist: &Value,
) -> Zeroizing<Bytes32> {
    let ss_pq = b32(expect, "ss_pq");
    assert_eq!(ss_pq.as_slice(), hx(nist, "k"), "ss_pq is NIST's");
    assert_eq!(fc.ct(), hx(nist, "c"), "ct is NIST's");
    let ek = acvp_ek_of_expanded_dk(nist);
    assert_eq!(ek, hx(given, "ek"));
    let viewing_ec = b32(given, "viewing_ec");
    let viewing = point(&hx(given, "viewing_pk_ec"));
    assert_eq!(pqsa_ec::public_point(&viewing_ec), Ok(viewing));
    assert_eq!(viewing, v5_09_point("viewing_pk_ec"));
    let ss_ec = pqsa_ec::ecdh(&viewing_ec, &fc.epk).expect("valid scalar and point");
    assert_eq!(encode(&*ss_ec), s(expect, "ss_ec"));
    let k = channel_key(&ss_ec, &ss_pq, &fc.epk, fc.ct(), &viewing, &ek).unwrap();
    assert_eq!(encode(&*k), s(expect, "k_pairwise"));
    k
}

fn vector_ids(doc: &Value) -> BTreeSet<&str> {
    obj(doc, "vectors")
        .as_object()
        .expect("vectors is an object")
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn vector_ids_match_inventory() {
    assert_eq!(
        vector_ids(section_1()),
        SECTION_1_CASES.iter().copied().collect()
    );
    assert_eq!(
        vector_ids(section_2()),
        SECTION_2_CASES.iter().copied().collect()
    );
}

// --- §1 ------------------------------------------------------------------

#[test]
fn v1_01_offset_of_ss() {
    let v = row(section_1(), "V1-01");
    let ss = b32(obj(v, "given"), "ss");
    let expect = obj(v, "expect");
    let base: Bytes32 = Sha256::digest([DS_OFFSET, &ss].concat()).into();
    assert_eq!(encode(&base), s(expect, "base"));
    let offset = offset_of(&ss).expect("this base is in range");
    assert_eq!(encode(&*offset), s(expect, "offset"));
}

#[test]
fn v1_02_to_v1_05_the_range_check() {
    let base = |id: &str| b32(obj(row(section_1(), id), "given"), "base");
    let v2 = row(section_1(), "V1-02");
    assert_eq!(
        encode(&base("V1-02")),
        s(obj(v2, "expect"), "offset_big_endian")
    );
    assert!(pqsa_ec::validate_scalar(&base("V1-02")).is_ok());
    assert_ne!(
        s(obj(v2, "expect"), "offset_big_endian"),
        s(obj(v2, "wrong"), "offset_little_endian")
    );
    for id in ["V1-03", "V1-04"] {
        assert_eq!(s(obj(row(section_1(), id), "expect"), "outcome"), "fail");
        assert_eq!(
            pqsa_ec::validate_scalar(&base(id)),
            Err(Error::NoValidScalar),
            "{id}"
        );
    }
    let v5 = row(section_1(), "V1-05");
    assert!(pqsa_ec::validate_scalar(&base("V1-05")).is_ok());
    assert_eq!(encode(&base("V1-05")), s(obj(v5, "expect"), "offset"));
}

#[test]
fn v1_07_view_tag_byte() {
    let v = row(section_1(), "V1-07");
    let tag = view_tag_of(&b32(obj(v, "given"), "ss"));
    assert_eq!(encode(&tag), s(obj(v, "expect"), "view_tag"));
    let wrong = obj(v, "wrong");
    for key in [
        "superseded_eight_byte_width",
        "trailing_byte_of_own_digest",
        "leading_byte_of_H_ss",
    ] {
        assert_ne!(encode(&tag), s(wrong, key));
    }
}

// --- §2: keys ------------------------------------------------------------

#[test]
fn v5_01_keygen_length() {
    let given = obj(row(section_2(), "V5-01"), "given");
    let seed = v5_09_seed();
    for length in u64_array(given, "lengths") {
        let length = usize::try_from(length).unwrap();
        let candidate = hx(obj(given, "seeds"), &length.to_string());
        assert_eq!(candidate.as_slice(), &seed[..length]);
        assert_eq!(
            keygen(&candidate).is_ok(),
            length == KEYGEN_SEED_BYTES,
            "{length}"
        );
    }
}

#[test]
fn v5_02_delegation_components() {
    let given = obj(row(section_2(), "V5-02"), "given");
    let spending = hx(given, "spending_seed");
    let planted = obj(given, "delegated_objects_by_component");
    for name in ["viewing_ec_seed", "d", "z"] {
        let seed = [spending.as_slice(), &hx(planted, name)].concat();
        assert!(
            matches!(keygen(&seed), Err(Error::SpendingKeyDelegated)),
            "{name}"
        );
    }
    let clean = obj(row(section_2(), "V5-02a"), "given");
    let seed = [hx(clean, "spending_seed"), hx(clean, "delegated")].concat();
    keygen(&seed).expect("positive control");
}

#[test]
fn v5_03_v5_11_v5_12_meta_address_decoding() {
    let v3 = obj(row(section_2(), "V5-03"), "given");
    assert!(MetaAddress::from_bytes(&hx(v3, "meta_address")).is_none());

    let v11 = obj(row(section_2(), "V5-11"), "given");
    for (len, ok) in [(1249, false), (1250, true), (1251, false)] {
        let bytes = hx(obj(v11, "meta_addresses"), &len.to_string());
        assert_eq!(MetaAddress::from_bytes(&bytes).is_some(), ok, "{len}");
    }

    let v12 = obj(row(section_2(), "V5-12"), "given");
    assert!(MetaAddress::from_bytes(&hx(v12, "meta_address_nonpoint")).is_none());
    assert!(MetaAddress::from_bytes(&hx(v12, "meta_address_valid")).is_some());
}

#[test]
fn v5_09_keygen_matches_nist_ek() {
    let (meta, master, tracking) = keygen(&v5_09_seed()).unwrap();
    let expect = v5_09();
    assert_eq!(encode(&meta.to_bytes()), s(expect, "meta_address"));
    assert_eq!(encode(meta.spending.as_bytes()), s(expect, "spending_pk"));
    assert_eq!(
        encode(meta.viewing_ec.as_bytes()),
        s(expect, "viewing_pk_ec")
    );
    assert_eq!(encode(&*tracking.to_bytes()), s(expect, "tracking"));
    assert_eq!(encode(&*master.spending_seed), s(expect, "master"));
    let kem_seed = &v5_09_seed()[64..];
    let nist = obj(acvp(), "keygen")
        .as_array()
        .unwrap()
        .iter()
        .find(|c| [hx(c, "d"), hx(c, "z")].concat() == kem_seed)
        .expect("an ACVP keygen case");
    assert_eq!(meta.ek(), hx(nist, "ek").as_slice(), "ek is NIST's");
}

#[test]
fn v5_10_scalars() {
    let seeds = obj(obj(row(section_2(), "V5-10"), "given"), "seeds");
    for (name, ok) in [
        ("spending_seed_0", false),
        ("spending_seed_n", false),
        ("spending_seed_n_minus_1", true),
        ("viewing_ec_seed_0", false),
    ] {
        let r = keygen(&hx(seeds, name));
        assert_eq!(r.is_ok(), ok, "{name}");
        if !ok {
            assert!(matches!(r, Err(Error::NoValidScalar)), "{name}");
        }
    }
}

// --- §1.1 and §2.4: the channel key ---------------------------------------

#[test]
fn v5_04_ecdh_is_the_x_coordinate() {
    let v = row(section_2(), "V5-04");
    let given = obj(v, "given");
    let ss_ec = pqsa_ec::ecdh(&b32(given, "esk"), &point(&hx(given, "viewing_pk_ec"))).unwrap();
    assert_eq!(encode(&*ss_ec), s(obj(v, "expect"), "ss_ec"));
}

#[test]
fn v5_05_v5_06_the_channel_key() {
    let v5 = row(section_2(), "V5-05");
    let given = obj(v5, "given");
    assert_eq!(s(given, "domain_separator").as_bytes(), DS_CHANNEL);
    let direct: Bytes32 = Sha3_256::digest([DS_CHANNEL, &hx(given, "ikm")].concat()).into();
    assert_eq!(encode(&direct), s(obj(v5, "expect"), "k_pairwise"));

    let v6 = row(section_2(), "V5-06");
    let k = channel_key_of(v5_06_parts());
    assert_eq!(encode(&*k), s(obj(v6, "expect"), "k_pairwise"));
    assert_eq!(*k, direct);
    let wrong = obj(v6, "wrong");
    assert_ne!(encode(&*k), s(wrong, "three_field_form"));
    assert_ne!(encode(&*k), s(wrong, "kem_only"));

    // The parts are what they say: epk = esk·G, ss_ec = ECDH(esk, viewing_pk_ec).x, and
    // (ct, ss_pq) = Encaps_internal(ek, m) for NIST's case.
    let g = obj(v6, "given");
    let parts = v5_06_parts();
    let esk = b32(g, "esk");
    assert_eq!(pqsa_ec::public_point(&esk), Ok(point(&hx(parts, "epk"))));
    let nist = acvp_case("encapsulation", u64_field(g, "acvp_encapsulation_tcId"));
    let (ct, ss_pq) =
        MlKem768::encapsulate(&hx(parts, "ek"), &hex::decode(s(g, "m")).unwrap()).unwrap();
    assert_eq!(ct, hx(nist, "c"));
    assert_eq!(encode(&*ss_pq), s(parts, "ss_pq"));
}

#[test]
fn v5_06a_06b_07_every_public_input_is_bound() {
    let parts = v5_06_parts();
    let k = |epk: &[u8], ct: &[u8], vpk: &[u8]| {
        channel_key(
            &b32(parts, "ss_ec"),
            &b32(parts, "ss_pq"),
            &point(epk),
            ct,
            &point(vpk),
            &hx(parts, "ek"),
        )
        .unwrap()
    };
    let (epk, ct, vpk) = (
        hx(parts, "epk"),
        hx(parts, "ct"),
        hx(parts, "viewing_pk_ec"),
    );

    let a = obj(row(section_2(), "V5-06a"), "given");
    let ea = obj(row(section_2(), "V5-06a"), "expect");
    assert_eq!(encode(&*k(&epk, &hx(a, "ct_a"), &vpk)), s(ea, "k_a"));
    assert_eq!(encode(&*k(&epk, &hx(a, "ct_b"), &vpk)), s(ea, "k_b"));
    assert_ne!(s(ea, "k_a"), s(ea, "k_b"));

    let b = obj(row(section_2(), "V5-06b"), "given");
    let eb = obj(row(section_2(), "V5-06b"), "expect");
    assert_eq!(
        pqsa_ec::public_point(&b32(b, "viewing_ec_b")),
        Ok(point(&hx(b, "viewing_pk_ec_b")))
    );
    assert_eq!(
        encode(&*k(&epk, &ct, &hx(b, "viewing_pk_ec_b"))),
        s(eb, "k_b")
    );
    assert_ne!(s(eb, "k_a"), s(eb, "k_b"));

    let c = obj(row(section_2(), "V5-07"), "given");
    let ec = obj(row(section_2(), "V5-07"), "expect");
    let flipped = hx(c, "epk_parity_flipped");
    assert_eq!(flipped[1..], epk[1..]);
    assert_eq!(encode(&*k(&flipped, &ct, &vpk)), s(ec, "k_b"));
    assert_ne!(s(ec, "k_a"), s(ec, "k_b"));
}

#[test]
fn v5_06c_an_erc8441_announcement_is_not_a_first_contact() {
    let v = row(section_2(), "V5-06c");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let parts = v5_06_parts();
    let s3 = hybrid_combine(
        s(given, "erc8441_domain_separator").as_bytes(),
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(parts, "epk")),
        &hx(parts, "ct"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .unwrap();
    assert_eq!(encode(&*s3), s(expect, "erc8441_ss"));
    let k = channel_key_of(parts);
    assert_eq!(encode(&*k), s(expect, "k_pairwise"));
    assert_ne!(*k, *s3);

    let ann = obj(given, "erc8441_announcement");
    let fc = first_contact(ann, &address(ann, "stealthAddress"));
    let spending = v5_09_point("spending_pk");
    let (tag, addr) = payment_at(&k, 0, &spending).unwrap();
    assert_eq!(encode(&tag), s(expect, "schemeId_5_view_tag_at_counter_0"));
    assert_eq!(encode(&addr), s(expect, "schemeId_5_address_at_counter_0"));
    assert!(counter_zero_match(k, &spending, &fc).is_none());
    assert!(s(expect, "outcome_under_schemeId_5").starts_with("skip"));
}

// --- §3: the wire --------------------------------------------------------

#[test]
fn v5_08_first_contact_wire() {
    let v = row(section_2(), "V5-08");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let k = Zeroizing::new(b32(given, "k_pairwise"));
    let (tag, addr) = payment_at(&k, 0, &point(&hx(given, "spending_pk"))).unwrap();
    let fc = FirstContact::new(point(&hx(given, "epk")), hx(given, "ct"), tag, addr).unwrap();
    let (a, e, m) = Announcement::FirstContact(fc).to_bytes();
    assert_eq!(encode(&a), s(expect, "stealthAddress"));
    assert_eq!(encode(&e), s(expect, "ephemeralPubKey"));
    assert_eq!(encode(&m), s(expect, "metadata"));
    assert_eq!(e.len() as u64, u64_field(expect, "ephemeralPubKey_bytes"));
    assert_eq!(
        (e.len() + m.len()) as u64,
        u64_field(expect, "payload_bytes")
    );
    // ct || epk has the right length and is a skip: its first 33 bytes are not a point here.
    let swapped = hx(obj(v, "wrong"), "ct_then_epk");
    assert_eq!(swapped.len(), EPHEMERAL_PUB_KEY_BYTES);
}

#[test]
fn v5_08a_view_tag_is_metadata_0() {
    let v = row(section_2(), "V5-08a");
    let given = obj(v, "given");
    let epk = hx(given, "ephemeralPubKey");
    for key in ["metadata_view_tag_only", "metadata_with_token_block"] {
        let parsed = Announcement::from_bytes(&[0; 20], &epk, &hx(given, key)).expect(key);
        let Announcement::FirstContact(fc) = parsed else {
            panic!("{key}")
        };
        assert_eq!(
            encode(&fc.view_tag),
            s(obj(v, "expect"), "view_tag_at_index_0")
        );
    }
}

#[test]
fn v5_15_announcement_shape() {
    let sec = section_2();
    let given = obj(row(sec, "V5-15"), "given");
    let honest_epk = hx(obj(row(sec, "V5-08"), "expect"), "ephemeralPubKey");
    let honest_md = hx(obj(row(sec, "V5-08"), "expect"), "metadata");
    for epk_len in u64_array(given, "ephemeralPubKey_lengths") {
        for md_len in u64_array(given, "metadata_lengths") {
            let epk = hx(obj(given, "ephemeralPubKeys"), &epk_len.to_string());
            let md = hx(obj(given, "metadatas"), &md_len.to_string());
            let (epk_len, md_len) = (epk_len as usize, md_len as usize);
            assert_eq!(epk, resized(&honest_epk, epk_len));
            assert_eq!(md, resized(&honest_md, md_len));
            let parsed = Announcement::from_bytes(&[0; 20], &epk, &md);
            let want = match (md_len, epk_len) {
                (0, _) => "skip",
                (_, 0) => "memo",
                (_, EPHEMERAL_PUB_KEY_BYTES) => "first contact",
                _ => "skip",
            };
            let got = match parsed {
                None => "skip",
                Some(Announcement::Memo(_)) => "memo",
                Some(Announcement::FirstContact(_)) => "first contact",
            };
            assert_eq!(got, want, "ephemeralPubKey {epk_len} metadata {md_len}");
            assert_eq!(v5_09_check(&[0; 20], &epk), Ok(false), "{epk_len}");
        }
    }
}

#[test]
fn v5_18_a_non_point_epk_is_a_skip() {
    let given = obj(row(section_2(), "V5-18"), "given");
    let metadata = hx(given, "metadata");
    let honest = hx(given, "honest_ephemeralPubKey");
    assert!(Announcement::from_bytes(&[0; 20], &honest, &metadata).is_some());
    let entries = obj(given, "ephemeralPubKeys").as_object().unwrap();
    assert_eq!(entries.len(), 5);
    for (name, field) in entries {
        let field = hex::decode(field.as_str().unwrap()).unwrap();
        assert_eq!(field.len(), EPHEMERAL_PUB_KEY_BYTES, "{name}");
        assert!(
            Announcement::from_bytes(&[0; 20], &field, &metadata).is_none(),
            "{name}"
        );
        assert_eq!(v5_09_check(&[0; 20], &field), Ok(false), "{name}");
    }
}

// --- §1, §2.8: the stealth key pair ---------------------------------------

#[test]
fn v5_13_v5_16_stealth_key_pair_and_address() {
    let v = row(section_2(), "V5-16");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let ss_0 = b32(given, "ss_0");
    let h = offset_of(&ss_0).unwrap();
    assert_eq!(encode(&*h), s(expect, "H_ss_0"));
    let spending = point(&hx(given, "spending_pk"));
    let stealth = pqsa_ec::add_points(&spending, &pqsa_ec::public_point(&h).unwrap()).unwrap();
    assert_eq!(encode(stealth.as_bytes()), s(expect, "stealth_pk"));
    let sk = pqsa_ec::add_scalars(&b32(given, "spending_sk"), &h).unwrap();
    assert_eq!(encode(&*sk), s(expect, "stealth_sk"));
    assert_eq!(pqsa_ec::public_point(&sk), Ok(stealth));
    assert_eq!(encode(&pqsa_ec::address_of(&stealth)), s(expect, "address"));
    let near = obj(expect, "near_n");
    let near_sk = pqsa_ec::add_scalars(&b32(given, "spending_sk_near_n"), &h).unwrap();
    assert_eq!(encode(&*near_sk), s(near, "stealth_sk"));
    assert_eq!(
        encode(pqsa_ec::public_point(&near_sk).unwrap().as_bytes()),
        s(near, "stealth_pk")
    );
    let master = Master {
        spending_seed: Zeroizing::new(b32(given, "spending_sk")),
    };
    let m = Match {
        stealth_address: address(expect, "address"),
        shared_secret: Zeroizing::new(ss_0),
        counter: 0,
        channel_key: Zeroizing::new([0; 32]),
    };
    assert_eq!(
        spend_key_bytes(&spend_key(&master, &m).unwrap()),
        sk.as_slice()
    );

    let v13 = row(section_2(), "V5-13");
    let g13 = obj(v13, "given");
    let e13 = obj(v13, "expect");
    let p13 = point(&hx(g13, "stealth_pk_compressed"));
    assert_eq!(p13, stealth);
    assert_eq!(encode(&pqsa_ec::address_of(&p13)), s(e13, "address"));
    let w13 = obj(v13, "wrong");
    for key in [
        "keccak_of_compressed",
        "keccak_with_0x04_prefix",
        "first_20_bytes_not_last_20",
    ] {
        assert_ne!(s(e13, "address"), s(w13, key));
    }
}

// --- §2.6: first contacts against an expanded-key recipient -----------------

#[test]
fn v5_14_a_tag_mismatch_retains_nothing() {
    let v = row(section_2(), "V5-14");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let nist = acvp_case("decapsulation", u64_field(given, "acvp_decapsulation_tcId"));
    assert_eq!(s(nist, "reason"), s(given, "acvp_reason"));
    let fcg = obj(given, "first_contact");
    let fc = first_contact(fcg, &address(fcg, "stealthAddress"));
    let k = expanded_recipient_key(given, expect, &fc, nist);
    let ss_0 = payment_secret(&k, 0);
    assert_eq!(encode(&*ss_0), s(expect, "ss_0"));
    let derived = view_tag_of(&ss_0);
    assert_eq!(encode(&derived), s(expect, "derived_view_tag"));
    assert_ne!(fc.view_tag, derived);

    let spending = point(&hx(given, "spending_pk"));
    let mut book = ScannerChannels::default();
    assert!(counter_zero_match(k.clone(), &spending, &fc).is_none());
    assert!(book.is_empty(), "skip, and no channel is retained");

    let mut corrected = fc.clone();
    corrected.view_tag = derived;
    let m = counter_zero_match(k.clone(), &spending, &corrected).expect("positive control");
    assert!(book.retain(&m.channel_key, spending));
    assert_eq!((m.counter, book.len()), (0, 1));
}

#[test]
fn v5_17_the_address_decides_a_first_contact() {
    let v = row(section_2(), "V5-17");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let nist = acvp_case("decapsulation", u64_field(given, "acvp_decapsulation_tcId"));
    let fcg = obj(given, "first_contact");
    let honest = first_contact(fcg, &address(given, "stealthAddress_honest"));
    let lie = first_contact(fcg, &address(given, "stealthAddress_lie"));
    let k = expanded_recipient_key(given, expect, &honest, nist);
    let ss_0 = payment_secret(&k, 0);
    assert_eq!(encode(&*ss_0), s(expect, "ss_0"));
    assert_eq!(encode(&view_tag_of(&ss_0)), s(expect, "view_tag"));
    assert_eq!(lie.view_tag, honest.view_tag, "the tag passes in both");

    let spending = point(&hx(given, "spending_pk"));
    assert!(counter_zero_match(k.clone(), &spending, &lie).is_none());
    let m = counter_zero_match(k, &spending, &honest).expect("honest");
    assert_eq!(encode(&m.stealth_address), s(expect, "address"));
}

#[test]
fn v5_19_an_ek_failing_the_key_check_is_an_error() {
    let given = obj(row(section_2(), "V5-19"), "given");
    let bad = MetaAddress::from_bytes(&hx(given, "meta_address_invalid_ek")).expect("points ok");
    let good = MetaAddress::from_bytes(&hx(given, "meta_address_valid_ek")).expect("points ok");
    let seed = [[0x22u8; 32], [0x44u8; 32]].concat();
    assert!(matches!(open(&bad, &seed), Err(Error::Kem)));
    assert!(matches!(open_random(&bad), Err(Error::Kem)));
    open(&good, &seed).expect("a valid ek encapsulates");
    assert_eq!(
        erc5564::generate_stealth_address(&hx(given, "meta_address_invalid_ek")).err(),
        Some(Error::Kem)
    );
}

// --- §2.5, §2.6: the channel ----------------------------------------------

#[test]
fn v5_20_payment_secrets() {
    let v = row(section_2(), "V5-20");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let k = b32(given, "k_pairwise");
    assert_eq!(
        encode(&k),
        s(obj(row(section_2(), "V5-06"), "expect"), "k_pairwise")
    );
    for c in str_array(given, "counters") {
        let ss = payment_secret(&k, c.parse::<u128>().expect("decimal"));
        assert_eq!(encode(&*ss), s(obj(expect, "ss_by_counter"), c));
        assert_eq!(
            encode(&view_tag_of(&ss)),
            s(obj(expect, "view_tag_by_counter"), c)
        );
    }
    let one = encode(&*payment_secret(&k, 1));
    let wrong = obj(v, "wrong");
    for key in [
        "counter_8_bytes",
        "counter_little_endian",
        "separator_appended",
    ] {
        assert_ne!(one, s(wrong, key));
    }
}

#[test]
fn v5_21_v5_22_counter_0_and_memos() {
    let v21 = row(section_2(), "V5-21");
    let k = Zeroizing::new(b32(obj(v21, "given"), "k_pairwise"));
    let spending = point(&hx(obj(v21, "given"), "spending_pk"));
    let (tag, addr) = payment_at(&k, 0, &spending).unwrap();
    let e21 = obj(v21, "expect");
    assert_eq!(encode(&tag), s(e21, "view_tag"));
    assert_eq!(encode(&addr), s(e21, "stealthAddress"));
    assert_eq!(encode(&*payment_secret(&k, 0)), s(e21, "ss_0"));

    // A sender whose channel this is pays counters 1, 2, 3 as V5-22's memos.
    let mut sender = SenderChannel {
        k_pairwise: k.clone(),
        spending,
        next: 1,
    };
    let v22 = row(section_2(), "V5-22");
    for want in obj(obj(v22, "expect"), "memos").as_array().unwrap() {
        let m = sender.pay().unwrap();
        let (a, e, md) = Announcement::Memo(m).to_bytes();
        assert_eq!(encode(&a), s(want, "stealthAddress"));
        assert_eq!(encode(&e), s(want, "ephemeralPubKey"));
        assert_eq!(encode(&md), s(want, "metadata"));
        assert_eq!(
            md.len() as u64,
            u64_field(obj(v22, "expect"), "payload_bytes")
        );
    }
    let at0 = obj(obj(v22, "wrong"), "memo_at_counter_0");
    assert_eq!(s(at0, "stealthAddress"), s(e21, "stealthAddress"));
}

#[test]
fn v5_23_the_window() {
    let v = row(section_2(), "V5-23");
    let given = obj(v, "given");
    assert_eq!(u64_field(given, "SCAN_LOOKAHEAD"), SCAN_LOOKAHEAD as u64);
    let (mut book, _k) = v5_06_book();
    let outcomes = str_array(obj(v, "expect"), "outcomes");
    let memos = obj(given, "memos_in_order").as_array().unwrap();
    assert_eq!(memos.len(), outcomes.len());
    for (m, want) in memos.iter().zip(outcomes) {
        let got = match book.match_memo(&memo(m)) {
            Some(hit) => format!("match at counter {}", hit.counter),
            None => "skip".to_owned(),
        };
        assert_eq!(
            got,
            want,
            "memo sent at counter {}",
            u64_field(m, "sent_at_counter")
        );
    }
}

#[test]
fn v5_24_the_address_decides_a_memo() {
    let v = row(section_2(), "V5-24");
    let given = obj(v, "given");
    let (mut book, _k) = v5_06_book();
    assert!(book.match_memo(&memo(obj(given, "memo_lie"))).is_none());
    assert_eq!(book.iter().next().unwrap().highest_counter(), 0);
    assert_eq!(
        book.match_memo(&memo(obj(given, "memo_honest")))
            .unwrap()
            .counter,
        1
    );
}

#[test]
fn v5_25_a_replayed_first_contact() {
    let v = row(section_2(), "V5-25");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let v17 = row(section_2(), "V5-17");
    let nist = acvp_case(
        "decapsulation",
        u64_field(obj(v17, "given"), "acvp_decapsulation_tcId"),
    );
    let fcg = obj(given, "first_contact");
    let fc = first_contact(fcg, &address(fcg, "stealthAddress"));
    let k = expanded_recipient_key(obj(v17, "given"), obj(v17, "expect"), &fc, nist);
    assert_eq!(encode(&*k), s(expect, "k_pairwise"));
    let spending = v5_09_point("spending_pk");

    // `admit`, with the decapsulation replaced by NIST's ss_pq.
    let admit = |book: &mut ScannerChannels| {
        counter_zero_match(k.clone(), &spending, &fc)
            .filter(|m| book.retain(&m.channel_key, spending))
    };
    let mut book = ScannerChannels::default();
    let outcomes = str_array(expect, "outcomes");
    assert_eq!(
        admit(&mut book).map(|m| m.counter),
        Some(0),
        "{}",
        outcomes[0]
    );
    let m1 = book.match_memo(&memo(obj(given, "memo_at_counter_1")));
    assert_eq!(m1.map(|m| m.counter), Some(1), "{}", outcomes[1]);
    assert!(admit(&mut book).is_none(), "{}", outcomes[2]);
    assert_eq!(book.len() as u64, u64_field(expect, "channels_retained"));
    assert_eq!(
        book.iter().next().unwrap().highest_counter() as u64,
        u64_field(expect, "highest_counter")
    );
}

#[test]
fn v5_26_keys_found_in_another_entry() {
    let v = row(section_2(), "V5-26");
    let given = obj(v, "given");
    let meta_bytes = hx(given, "schemeId_5_meta_address");
    assert_eq!(meta_bytes, hx(v5_09(), "meta_address"));
    let meta = MetaAddress::from_bytes(&meta_bytes).expect("V5-09's meta-address");
    let outcomes = obj(obj(v, "expect"), "outcomes")
        .as_object()
        .expect("an object");
    let entries = obj(given, "other_entries").as_object().expect("an object");
    assert_eq!(entries.len(), 7);
    for (name, entry) in entries {
        let entry = hex::decode(entry.as_str().expect("hex")).expect("hex");
        let want = outcomes[name].as_str().expect("a string");
        let got = if meta.shares_keys_with(&entry) {
            "do not pay under schemeId 5"
        } else {
            "pay"
        };
        assert_eq!(got, want, "{name}");
    }
}
