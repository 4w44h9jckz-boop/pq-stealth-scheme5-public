//! Deterministic fixture for the gas benchmarks: one channel, its first contact (counter 0)
//! and its first memo (counter 1), each with the one-time key that spends it.
//!
//! The keys and seeds are fixed demonstration values, so this prints REAL private keys for
//! the demonstration recipient. Never fund them anywhere but a local node.
use pqsa_channel::{Announcement, Match, NAME, SCHEME_ID, ScannerChannels};
use pqsa_core::SenderState;
use serde_json::{Value, json};

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn payment(a: &Announcement, m: &Match, master: &pqsa_channel::Master) -> Value {
    let (address, ephemeral_pub_key, metadata) = a.to_bytes();
    assert_eq!(
        address, m.stealth_address,
        "the scanner derives the announced address"
    );
    let key = pqsa_channel::spend_key(master, m).expect("fixture spend key");
    json!({
        "counter": u64::try_from(m.counter).expect("small counter"),
        "stealth_address": prefixed_hex(&address),
        "spend_key": prefixed_hex(pqsa_channel::spend_key_bytes(&key)),
        "ephemeral_pub_key": prefixed_hex(&ephemeral_pub_key),
        "metadata": prefixed_hex(&metadata),
    })
}

fn main() {
    // The demonstration keygen seed: the same 128 bytes, and so the same meta-address, as
    // the schemeId 3 tree's fixture.
    let seed: Vec<u8> = (0..128u32)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
        .collect();
    let (meta, master, tracking) = pqsa_channel::keygen(&seed).expect("fixture key generation");
    let mut sender = SenderState::resume(&[0x5a; 32], 0);
    let (first_contact, mut channel) = sender
        .retrying(
            SCHEME_ID,
            NAME,
            pqsa_channel::FIRST_CONTACT_SEED_BYTES,
            4,
            |s| pqsa_channel::open(&meta, s),
        )
        .expect("fixture first contact");
    let memo = channel.pay().expect("fixture memo");

    let scanner = pqsa_channel::bind(&tracking, &meta).expect("fixture scanner binding");
    let mut book = ScannerChannels::default();
    let fc = Announcement::FirstContact(first_contact);
    let memo = Announcement::Memo(memo);
    let m0 = book
        .scan(&scanner, &fc)
        .expect("the first contact must scan");
    let m1 = book.scan(&scanner, &memo).expect("the memo must scan");
    println!(
        "{}",
        json!({
            "name": "scheme5-demo-v1",
            "scheme_id": SCHEME_ID,
            "meta_address": prefixed_hex(&meta.to_bytes()),
            "first_contact": payment(&fc, &m0, &master),
            "memo": payment(&memo, &m1, &master),
        })
    );
}
