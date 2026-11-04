//! Unit tests. The conformance vectors run in `spec_vectors.rs`.

use super::*;

/// Spending scalar 0x11.., viewing scalar, then the `(d, z)` of ACVP keygen tcId 26.
fn seed128() -> Vec<u8> {
    let mut out = vec![0x11u8; 32];
    out.extend((0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(3)));
    out.extend(
        hex::decode(concat!(
            "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0",
            "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0"
        ))
        .unwrap(),
    );
    out
}

fn stranger() -> Vec<u8> {
    [[0x21u8; 32].as_slice(), &[0x42; 32], &[0x63; 64]].concat()
}

/// A channel opened from a fixed seed, with the recipient's scanner and an empty book.
fn fixture() -> (MetaAddress, Master, Scanner, FirstContact, SenderChannel) {
    let (meta, master, tracking) = keygen(&seed128()).unwrap();
    let scanner = bind(&tracking, &meta).unwrap();
    let (fc, ch) = open(&meta, &[0x33; 64]).unwrap();
    (meta, master, scanner, fc, ch)
}

fn wire(a: &Announcement) -> Announcement {
    let (addr, epk, metadata) = a.to_bytes();
    Announcement::from_bytes(&addr, &epk, &metadata).expect("round trip")
}

#[test]
fn secret_fields_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let (_, master, _, _, ch) = fixture();
    assert_zeroize_on_drop(&master.spending_seed);
    assert_zeroize_on_drop(&ch.k_pairwise);
    assert_zeroize_on_drop(&ch.to_bytes());
}

#[test]
fn redaction_leaks_no_secret() {
    let (meta, master, scanner, fc, ch) = fixture();
    let (_, _, tracking) = keygen(&seed128()).unwrap();
    let mut book = ScannerChannels::default();
    let m = book.admit(&scanner, &fc).unwrap();
    let secrets = [
        hex::encode(*master.spending_seed),
        hex::encode(*tracking.viewing_ec_seed),
        hex::encode(&*tracking.kem_seed),
        hex::encode(*m.shared_secret),
        hex::encode(*m.channel_key),
    ];
    let printed = format!(
        "{master:?} {tracking:?} {scanner:?} {m:?} {ch:?} {book:?} {:?}",
        book.iter().next().unwrap()
    );
    for s in secrets {
        assert!(!printed.contains(&s), "Debug output leaks a secret");
    }
    assert!(printed.contains("[REDACTED]"));
    let _ = meta;
}

#[test]
fn bind_catches_a_corrupt_kem_seed_and_a_wrong_viewing_seed() {
    let (meta, _, tracking) = keygen(&seed128()).unwrap();
    let mut bad = tracking.clone();
    bad.kem_seed[0] ^= 1;
    assert!(matches!(bind(&bad, &meta), Err(Error::TrackingKeyMismatch)));
    let mut bad = tracking.clone();
    bad.viewing_ec_seed[31] ^= 1;
    assert!(matches!(bind(&bad, &meta), Err(Error::TrackingKeyMismatch)));
    let (_, _, theirs) = keygen(&stranger()).unwrap();
    assert!(matches!(
        bind(&theirs, &meta),
        Err(Error::TrackingKeyMismatch)
    ));
}

#[test]
fn keygen_rejects_bad_seeds() {
    let s = seed128();
    assert!(matches!(keygen(&s[..96]), Err(Error::Malformed)));
    assert!(matches!(
        keygen(&[s.as_slice(), &[0]].concat()),
        Err(Error::Malformed)
    ));
    for at in [32usize, 64, 96] {
        let mut t = s.clone();
        let spending = t[..32].to_vec();
        t[at..at + 32].copy_from_slice(&spending);
        assert!(
            matches!(keygen(&t), Err(Error::SpendingKeyDelegated)),
            "{at}"
        );
    }
    let mut t = s.clone();
    t[..32].fill(0);
    assert!(matches!(keygen(&t), Err(Error::NoValidScalar)));
}

#[test]
fn a_channel_round_trips_over_the_wire() {
    let (_, master, scanner, fc, mut ch) = fixture();
    let mut book = ScannerChannels::default();
    let first = book
        .scan(&scanner, &wire(&Announcement::FirstContact(fc.clone())))
        .expect("the first contact is ours");
    assert_eq!(first.counter, 0);
    assert_eq!(first.stealth_address, fc.stealth_address);
    assert_eq!(book.len(), 1);
    for i in 1..=50u128 {
        let memo = ch.pay().unwrap();
        let (_, epk, metadata) = Announcement::Memo(memo).to_bytes();
        assert!(epk.is_empty());
        assert_eq!(
            metadata.len(),
            1,
            "a memo is the one-byte view tag and nothing else"
        );
        let m = book
            .scan(&scanner, &wire(&Announcement::Memo(memo)))
            .unwrap_or_else(|| panic!("memo at counter {i}"));
        assert_eq!(m.counter, i);
        assert_eq!(*m.channel_key, *first.channel_key);
        let key = spend_key(&master, &m).unwrap();
        let address = pqsa_ec::address_of(
            &pqsa_ec::public_point(spend_key_bytes(&key).try_into().unwrap()).unwrap(),
        );
        assert_eq!(address, memo.stealth_address);
    }
    assert_eq!(ch.next_counter(), 51);
}

#[test]
fn a_strangers_first_contact_is_not_retained() {
    let (meta, _, scanner, _, _) = fixture();
    let (theirs, _, _) = keygen(&stranger()).unwrap();
    let mut book = ScannerChannels::default();
    for i in 0..8u8 {
        let (fc, _) = open(&theirs, &[i + 1; 64]).unwrap();
        assert!(book.admit(&scanner, &fc).is_none());
    }
    assert!(
        book.is_empty(),
        "decapsulation alone MUST NOT admit a channel"
    );
    let _ = meta;
}

#[test]
fn a_first_contact_with_a_lying_address_is_not_retained() {
    let (_, _, scanner, mut fc, _) = fixture();
    fc.stealth_address[0] ^= 1;
    let mut book = ScannerChannels::default();
    assert!(book.admit(&scanner, &fc).is_none());
    assert!(book.is_empty());
}

#[test]
fn a_replayed_first_contact_is_one_channel_and_no_second_payment() {
    let (_, _, scanner, fc, mut ch) = fixture();
    let mut book = ScannerChannels::default();
    assert!(book.admit(&scanner, &fc).is_some());
    let memo = ch.pay().unwrap();
    assert_eq!(book.match_memo(&memo).unwrap().counter, 1);
    assert!(
        book.admit(&scanner, &fc).is_none(),
        "the replay reports no payment"
    );
    assert_eq!(book.len(), 1);
    assert_eq!(
        book.iter().next().unwrap().highest_counter(),
        1,
        "and does not rewind the channel"
    );
}

#[test]
fn a_replayed_memo_matches_once() {
    let (_, _, scanner, fc, mut ch) = fixture();
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    let memo = ch.pay().unwrap();
    assert!(book.match_memo(&memo).is_some());
    assert!(book.match_memo(&memo).is_none());
}

#[test]
fn a_memo_with_a_lying_address_is_a_skip() {
    let (_, _, scanner, fc, mut ch) = fixture();
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    let mut memo = ch.pay().unwrap();
    memo.stealth_address[5] ^= 0x40;
    assert!(book.match_memo(&memo).is_none());
    assert_eq!(book.iter().next().unwrap().highest_counter(), 0);
}

#[test]
fn out_of_order_memos_inside_the_band_are_found() {
    let (_, _, scanner, fc, mut ch) = fixture();
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    let memos: Vec<Memo> = (0..5).map(|_| ch.pay().unwrap()).collect();
    // Counters 1..=5 arrive as 5, 3, 1, 4, 2.
    for (idx, want) in [(4usize, 5u128), (2, 3), (0, 1), (3, 4), (1, 2)] {
        assert_eq!(book.match_memo(&memos[idx]).unwrap().counter, want);
    }
}

#[test]
fn the_window_edges() {
    let (_, _, scanner, fc, mut ch) = fixture();
    let l = SCAN_LOOKAHEAD as u128;
    let memos: Vec<Memo> = (0..3 * l).map(|_| ch.pay().unwrap()).collect();
    let memo_at = |c: u128| memos[(c - 1) as usize];

    // Above: counter L is the last one tried from high = 0; L + 1 is not.
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    assert!(book.match_memo(&memo_at(l + 1)).is_none());
    assert_eq!(book.match_memo(&memo_at(l)).unwrap().counter, l);

    // Below: with high = 2L, counter L + 1 is in the band and counter L is not.
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    for c in (l..=2 * l).step_by(l as usize) {
        book.match_memo(&memo_at(c)).unwrap();
    }
    assert_eq!(book.iter().next().unwrap().highest_counter(), 2 * l);
    assert_eq!(book.match_memo(&memo_at(l + 1)).unwrap().counter, l + 1);
    assert!(book.match_memo(&memo_at(l - 1)).is_none());
}

#[test]
fn a_wider_window_recovers_what_the_default_misses() {
    let (_, _, scanner, fc, mut ch) = fixture();
    for _ in 0..40 {
        ch.pay().unwrap();
    }
    let late = ch.pay().unwrap(); // counter 41
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    assert!(book.match_memo(&late).is_none());

    let mut wide = ScannerChannels::with_lookahead(64).unwrap();
    wide.admit(&scanner, &fc).unwrap();
    assert_eq!(wide.match_memo(&late).unwrap().counter, 41);
    assert!(ScannerChannels::with_lookahead(SCAN_LOOKAHEAD - 1).is_err());
}

#[test]
fn two_channels_to_one_recipient_stay_apart() {
    let (meta, _, scanner, fc_a, mut a) = fixture();
    let (fc_b, mut b) = open(&meta, &[0x44; 64]).unwrap();
    let mut book = ScannerChannels::default();
    let ka = book.admit(&scanner, &fc_a).unwrap().channel_key;
    let kb = book.admit(&scanner, &fc_b).unwrap().channel_key;
    assert_ne!(*ka, *kb);
    for _ in 0..5 {
        assert_eq!(
            *book.match_memo(&b.pay().unwrap()).unwrap().channel_key,
            *kb
        );
        assert_eq!(
            *book.match_memo(&a.pay().unwrap()).unwrap().channel_key,
            *ka
        );
    }
}

#[test]
fn persistence_is_role_tagged_and_round_trips() {
    let (_, _, scanner, fc, mut ch) = fixture();
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    let memos: Vec<Memo> = (0..6).map(|_| ch.pay().unwrap()).collect();
    for i in [0usize, 1, 4] {
        book.match_memo(&memos[i]).unwrap();
    }

    let sender_bytes = ch.to_bytes();
    assert_eq!(sender_bytes.len(), 82);
    assert_eq!(sender_bytes[0], ROLE_SENDER);
    let scanner_bytes = book.iter().next().unwrap().to_bytes();
    assert_eq!(scanner_bytes[0], ROLE_SCANNER);
    assert_eq!(scanner_bytes.len(), 86 + SCAN_LOOKAHEAD.div_ceil(8));

    assert!(ScannerChannel::from_bytes(&sender_bytes).is_err());
    assert!(SenderChannel::from_bytes(&scanner_bytes).is_err());
    let mut relabelled = scanner_bytes.to_vec();
    relabelled[0] = ROLE_SENDER;
    assert!(
        SenderChannel::from_bytes(&relabelled).is_err(),
        "and the lengths differ"
    );

    let mut restored_sender = SenderChannel::from_bytes(&sender_bytes).unwrap();
    assert_eq!(restored_sender.next_counter(), 7);
    let restored = ScannerChannel::from_bytes(&scanner_bytes).unwrap();
    let mut book2 = ScannerChannels::default();
    assert!(book2.restore(restored.clone()));
    assert!(!book2.restore(restored), "a key is retained once");
    // Counters 3, 4 and 6 are still owed; 1, 2 and 5 were matched before the restart.
    assert!(book2.match_memo(&memos[0]).is_none());
    assert_eq!(book2.match_memo(&memos[3]).unwrap().counter, 4);
    assert_eq!(book2.match_memo(&memos[2]).unwrap().counter, 3);
    assert_eq!(book2.match_memo(&memos[5]).unwrap().counter, 6);
    assert_eq!(
        book2
            .match_memo(&restored_sender.pay().unwrap())
            .unwrap()
            .counter,
        7
    );
}

#[test]
fn corrupt_scanner_records_are_refused() {
    let (_, _, scanner, fc, _) = fixture();
    let mut book = ScannerChannels::default();
    book.admit(&scanner, &fc).unwrap();
    let good = book.iter().next().unwrap().to_bytes().to_vec();
    // `high` not marked matched.
    let mut b = good.clone();
    b[86] = 0;
    assert!(ScannerChannel::from_bytes(&b).is_err());
    // A bit for a counter below 0 (high = 0, bit 1).
    let mut b = good.clone();
    b[86] |= 0b10;
    assert!(ScannerChannel::from_bytes(&b).is_err());
    // Lookahead 0, and one past the ceiling, before any allocation.
    let mut b = good.clone();
    b[82..86].copy_from_slice(&0u32.to_be_bytes());
    assert!(ScannerChannel::from_bytes(&b).is_err());
    let mut b = good.clone();
    b[82..86].copy_from_slice(&((SCAN_LOOKAHEAD_MAX + 1) as u32).to_be_bytes());
    assert!(ScannerChannel::from_bytes(&b).is_err());
    assert!(ScannerChannel::from_bytes(&good[..good.len() - 1]).is_err());
    assert!(ScannerChannel::from_bytes(&good).is_ok());
}

#[test]
fn a_sender_record_at_counter_zero_or_the_top_is_refused_or_exhausted() {
    let (_, _, _, _, ch) = fixture();
    let mut b = ch.to_bytes().to_vec();
    b[66..82].copy_from_slice(&0u128.to_be_bytes());
    assert!(SenderChannel::from_bytes(&b).is_err());
    b[66..82].copy_from_slice(&u128::MAX.to_be_bytes());
    let mut top = SenderChannel::from_bytes(&b).unwrap();
    assert!(matches!(top.pay(), Err(Error::CounterExhausted)));
    assert_eq!(
        top.next_counter(),
        u128::MAX,
        "a refused payment consumes nothing"
    );
}

#[test]
fn open_rejects_bad_seed_lengths_and_invalid_ephemeral_scalars() {
    let (meta, _, _) = keygen(&seed128()).unwrap();
    assert!(matches!(open(&meta, &[0x33; 63]), Err(Error::Malformed)));
    assert!(matches!(open(&meta, &[0x33; 65]), Err(Error::Malformed)));
    let mut zero = [0x33u8; 64];
    zero[..32].fill(0);
    assert!(matches!(open(&meta, &zero), Err(Error::SeedRejected)));
    let mut big = [0xffu8; 64];
    big[32..].fill(0x33);
    assert!(matches!(open(&meta, &big), Err(Error::SeedRejected)));
}

#[test]
fn a_random_first_contact_round_trips_and_is_fresh() {
    let (meta, _, tracking) = keygen(&seed128()).unwrap();
    let scanner = bind(&tracking, &meta).unwrap();
    let (a, _) = open_random(&meta).unwrap();
    let (b, _) = open_random(&meta).unwrap();
    assert_ne!(a.epk, b.epk);
    assert_ne!(a.ct(), b.ct());
    let mut book = ScannerChannels::default();
    assert!(book.admit(&scanner, &a).is_some());
    assert!(book.admit(&scanner, &b).is_some());
    assert_eq!(book.len(), 2);
}

#[test]
fn wire_shapes_and_skips() {
    let (_, _, _, fc, mut ch) = fixture();
    let (addr, epk_ct, tag) = Announcement::FirstContact(fc.clone()).to_bytes();
    assert_eq!(epk_ct.len(), EPHEMERAL_PUB_KEY_BYTES);
    assert_eq!(tag.len(), 1);
    // ERC-5564 token metadata after the tag is ignored.
    let token = [tag.as_slice(), &[0xee; 56]].concat();
    assert_eq!(
        Announcement::from_bytes(&addr, &epk_ct, &token),
        Some(Announcement::FirstContact(fc.clone()))
    );
    assert!(Announcement::from_bytes(&addr, &epk_ct, &[]).is_none());
    for n in [1usize, 33, 1120, 1122] {
        let field = epk_ct
            .iter()
            .copied()
            .chain(std::iter::repeat(0x11))
            .take(n)
            .collect::<Vec<_>>();
        assert!(
            Announcement::from_bytes(&addr, &field, &tag).is_none(),
            "{n}"
        );
    }
    let compact = [&[0x05][..], &epk_ct[1..]].concat();
    assert!(Announcement::from_bytes(&addr, &compact, &tag).is_none());

    let memo = ch.pay().unwrap();
    let (maddr, mepk, mmeta) = Announcement::Memo(memo).to_bytes();
    assert_eq!(
        Announcement::from_bytes(&maddr, &mepk, &mmeta),
        Some(Announcement::Memo(memo))
    );
    assert!(Announcement::from_bytes(&maddr, &mepk, &[]).is_none());
    assert!(Announcement::from_event(3, &addr, &epk_ct, &tag).is_none());
    assert!(Announcement::from_event(5, &addr, &epk_ct, &tag).is_some());
}

#[test]
fn a_retired_channel_resumes_without_rescanning_first_contacts() {
    let (_, _, scanner, fc, mut ch) = fixture();
    let mut book = ScannerChannels::default();
    let key = book.admit(&scanner, &fc).unwrap().channel_key;
    let retired = book.retire(&key).unwrap();
    let saved = retired.to_bytes();
    let memo = ch.pay().unwrap();
    assert!(
        book.match_memo(&memo).is_none(),
        "a retired channel is not derived"
    );
    book.restore(ScannerChannel::from_bytes(&saved).unwrap());
    assert_eq!(book.match_memo(&memo).unwrap().counter, 1);
}

#[test]
fn a_counter_whose_offset_fails_is_skipped_by_the_sender() {
    // No findable counter fails §1's range check, so the skip is exercised on its own: the
    // sender's loop only advances `next` past such a counter, and the scanner's window derives
    // tags without the offset. What is checkable is that counters are consumed one at a time.
    let (_, _, _, _, mut ch) = fixture();
    for want in 1..=5u128 {
        assert_eq!(ch.next_counter(), want);
        ch.pay().unwrap();
    }
}

#[test]
fn the_channel_key_is_not_schemeid3s_payment_secret() {
    let (meta, _, _) = keygen(&seed128()).unwrap();
    let esk = [0x22u8; 32];
    let epk = pqsa_ec::public_point(&esk).unwrap();
    let ss_ec = pqsa_ec::ecdh(&esk, &meta.viewing_ec).unwrap();
    let (ct, ss_pq) = MlKem768::encapsulate(meta.ek(), &[0x33; 32]).unwrap();
    let k = channel_key(&ss_ec, &ss_pq, &epk, &ct, &meta.viewing_ec, meta.ek()).unwrap();
    let s3 = hybrid_combine(
        b"pq-stealth/hybrid-payment/v1",
        &ss_ec,
        &ss_pq,
        &epk,
        &ct,
        &meta.viewing_ec,
        meta.ek(),
    )
    .unwrap();
    assert_ne!(*k, *s3);
}

#[test]
fn a_first_contact_is_not_a_schemeid3_payment() {
    // §2.3 forbids registering the same keys under schemeId 3 and 5. If a recipient did anyway,
    // a schemeId 3 scanner running ERC-8441's combiner over a first contact's fields could
    // match its view tag by chance, but never its address.
    let (meta, _, tracking) = keygen(&seed128()).unwrap();
    let (fc, _) = open(&meta, &[0x33; 64]).unwrap();
    let ss_ec = pqsa_ec::ecdh(&tracking.viewing_ec_seed, &fc.epk).unwrap();
    let ss_pq = MlKem768::decapsulate(&tracking.kem_seed, fc.ct()).unwrap();
    let ss3 = hybrid_combine(
        b"pq-stealth/hybrid-payment/v1",
        &ss_ec,
        &ss_pq,
        &fc.epk,
        fc.ct(),
        &meta.viewing_ec,
        meta.ek(),
    )
    .unwrap();
    assert_ne!(
        stealth_address_of(&meta.spending, &ss3).unwrap(),
        fc.stealth_address
    );
}

#[test]
fn keys_found_in_another_registry_entry_are_reported() {
    let (meta, _, _) = keygen(&seed128()).unwrap();
    let (theirs, _, _) = keygen(&stranger()).unwrap();
    let own = meta.to_bytes();
    // ERC-8441 encodes its meta-address the same way, so the same bytes under schemeId 3.
    assert!(meta.shares_keys_with(&own));
    // Each key on its own, inside another scheme's encoding.
    let schemeid1 =
        |a: &CompressedPoint, b: &CompressedPoint| [a.as_bytes().as_slice(), b.as_bytes()].concat();
    assert!(meta.shares_keys_with(&schemeid1(&meta.spending, &theirs.viewing_ec)));
    assert!(meta.shares_keys_with(&schemeid1(&theirs.spending, &meta.viewing_ec)));
    let same_ek = [
        theirs.spending.as_bytes().as_slice(),
        theirs.viewing_ec.as_bytes(),
        meta.ek(),
    ]
    .concat();
    assert!(meta.shares_keys_with(&same_ek));
    // Unrelated keys, and an empty (cleared) entry.
    assert!(!meta.shares_keys_with(&theirs.to_bytes()));
    assert!(!meta.shares_keys_with(&schemeid1(&theirs.spending, &theirs.viewing_ec)));
    assert!(!meta.shares_keys_with(&[]));
}
