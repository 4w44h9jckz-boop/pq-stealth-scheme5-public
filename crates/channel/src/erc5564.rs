//! ERC-5564's three methods for `schemeId` 5, as §2.10 defines them, over bytes.
//!
//! ERC-5564's methods are stateless, and a schemeId 5 memo can only be checked with the
//! channel state its first contact created. So these methods cover the FIRST CONTACT, the
//! payment at counter 0, which is self-contained; memos go through
//! [`ScannerChannels`](crate::ScannerChannels).
//!
//! `viewingKey`, `spendingPubKey` and `spendingKey` are the caller's own keys, so a malformed
//! one is an error in every method, never `false`. Announcement bytes that §2.9 makes a skip,
//! and a memo's empty `ephemeralPubKey`, are `Ok(false)` in [`check_stealth_address`].

use crate::{
    Announcement, MetaAddress, SpendKey, open_random, payment_secret, scanner_unchecked,
    spend_key_from, stealth_address_of,
};
use pqsa_core::{Bytes32, Error, VIEW_TAG_BYTES};
use pqsa_kem::{Kem, MlKem768};

/// `viewingKey` length: the tracking key `viewing_ec ‖ d ‖ z`. §2.1.
pub const VIEWING_KEY_BYTES: usize = 32 + MlKem768::KEYGEN_SEED_BYTES;

/// What `generateStealthAddress` returns: `(stealthAddress, ephemeralPubKey, viewTag)`.
pub type GeneratedStealthAddress = ([u8; 20], Vec<u8>, [u8; VIEW_TAG_BYTES]);

/// `generateStealthAddress(stealthMetaAddress)`: a first contact (§2.4) with randomness from
/// the operating system's CSPRNG.
///
/// It returns no channel key, so the channel it opens carries no later payment. A sender that
/// wants the channel calls [`open_random`] and keeps the [`SenderChannel`](crate::SenderChannel).
///
/// # Errors
///
/// [`Error::Malformed`] if `stealth_meta_address` does not decode (§2.2); [`Error::Kem`] if its
/// `ek` fails FIPS 203's encapsulation key check; [`Error::Rng`] if the RNG fails.
pub fn generate_stealth_address(
    stealth_meta_address: &[u8],
) -> Result<GeneratedStealthAddress, Error> {
    let meta = MetaAddress::from_bytes(stealth_meta_address).ok_or(Error::Malformed)?;
    let (fc, _channel) = open_random(&meta)?;
    let view_tag = fc.view_tag;
    let (stealth_address, ephemeral_pub_key, _) = Announcement::FirstContact(fc).to_bytes();
    Ok((stealth_address, ephemeral_pub_key, view_tag))
}

/// `checkStealthAddress(stealthAddress, ephemeralPubKey, viewingKey, spendingPubKey)` for a
/// first contact: §2.6 at counter 0, with no view tag passed in, so the address decides.
///
/// `Ok(false)` for a memo (empty `ephemeralPubKey`), which needs channel state, and wherever
/// §2.9 says skip.
///
/// # Errors
///
/// [`Error::Malformed`] if `viewing_key` is not [`VIEWING_KEY_BYTES`] or `spending_pub_key` is
/// not a valid compressed point; [`Error::NoValidScalar`] if `viewing_ec` is not a valid scalar.
pub fn check_stealth_address(
    stealth_address: &[u8; 20],
    ephemeral_pub_key: &[u8],
    viewing_key: &[u8],
    spending_pub_key: &[u8],
) -> Result<bool, Error> {
    let scanner = scanner_unchecked(viewing_key, pqsa_ec::decode_point(spending_pub_key)?)?;
    // ERC-5564 passes no metadata here, so the parse gets a placeholder view tag and the
    // address alone decides.
    let Some(Announcement::FirstContact(fc)) =
        Announcement::from_bytes(stealth_address, ephemeral_pub_key, &[0])
    else {
        return Ok(false);
    };
    let Some(ss_0) = counter_zero_secret(&scanner, &fc) else {
        return Ok(false);
    };
    Ok(stealth_address_of(&scanner.spending, &ss_0).is_ok_and(|a| a == *stealth_address))
}

/// `computeStealthKey(stealthAddress, ephemeralPubKey, viewingKey, spendingKey)` for a first
/// contact: §2.8 at counter 0.
///
/// Fails rather than return a key that does not control `stealth_address`.
///
/// # Errors
///
/// As [`check_stealth_address`] for `viewing_key`; [`Error::Malformed`] if `spending_key` is not
/// 32 bytes or `ephemeral_pub_key` is not a first contact; [`Error::NoValidScalar`] if
/// `spending_key` is not a valid scalar; [`Error::MasterKeyMismatch`] if the key derived from
/// these inputs does not control `stealth_address`.
pub fn compute_stealth_key(
    stealth_address: &[u8; 20],
    ephemeral_pub_key: &[u8],
    viewing_key: &[u8],
    spending_key: &[u8],
) -> Result<SpendKey, Error> {
    let spending_seed: &Bytes32 = spending_key.try_into().map_err(|_| Error::Malformed)?;
    let scanner = scanner_unchecked(viewing_key, pqsa_ec::public_point(spending_seed)?)?;
    let Some(Announcement::FirstContact(fc)) =
        Announcement::from_bytes(stealth_address, ephemeral_pub_key, &[0])
    else {
        return Err(Error::Malformed);
    };
    let ss_0 = counter_zero_secret(&scanner, &fc).ok_or(Error::Malformed)?;
    spend_key_from(spending_seed, &ss_0, stealth_address)
}

/// `ss_0` for this scanner and first contact, whoever it was addressed to.
fn counter_zero_secret(
    scanner: &crate::Scanner,
    fc: &crate::FirstContact,
) -> Option<zeroize::Zeroizing<Bytes32>> {
    let ss_ec = pqsa_ec::ecdh(&scanner.viewing_ec_seed, &fc.epk).ok()?;
    let ss_pq = MlKem768::decapsulate(&scanner.kem_seed, fc.ct()).ok()?;
    let k = crate::channel_key(
        &ss_ec,
        &ss_pq,
        &fc.epk,
        fc.ct(),
        &scanner.viewing_pk_ec,
        &scanner.ek,
    )
    .ok()?;
    Some(payment_secret(&k, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Master, ScannerChannels, Tracking, bind, keygen, spend_key, spend_key_bytes};

    struct Recipient {
        meta: MetaAddress,
        master: Master,
        tracking: Tracking,
        meta_bytes: Vec<u8>,
        viewing_key: Vec<u8>,
        spending_pub_key: Vec<u8>,
    }

    fn recipient(seed: &[u8]) -> Recipient {
        let (meta, master, tracking) = keygen(seed).expect("valid seed");
        Recipient {
            meta_bytes: meta.to_bytes(),
            spending_pub_key: meta.spending.as_bytes().to_vec(),
            viewing_key: tracking.to_bytes().to_vec(),
            meta,
            master,
            tracking,
        }
    }

    /// The demonstration's keygen seed.
    fn ours() -> Recipient {
        recipient(
            &(0..128u8)
                .map(|i| i.wrapping_mul(7).wrapping_add(3))
                .collect::<Vec<_>>(),
        )
    }

    fn theirs() -> Recipient {
        recipient(&[[0x21u8; 32].as_slice(), &[0x42; 32], &[0x63; 64]].concat())
    }

    #[test]
    fn generate_check_and_compute_agree_with_the_scanner() {
        let r = ours();
        assert_eq!(r.viewing_key.len(), VIEWING_KEY_BYTES);
        let (addr, epk_ct, tag) = generate_stealth_address(&r.meta_bytes).unwrap();
        assert_eq!(epk_ct.len(), crate::EPHEMERAL_PUB_KEY_BYTES);
        assert!(
            check_stealth_address(&addr, &epk_ct, &r.viewing_key, &r.spending_pub_key).unwrap()
        );

        let scanner = bind(&r.tracking, &r.meta).unwrap();
        let ann = Announcement::from_bytes(&addr, &epk_ct, &tag).unwrap();
        let m = ScannerChannels::default()
            .scan(&scanner, &ann)
            .expect("ours");
        assert_eq!(m.counter, 0);

        let k1 =
            compute_stealth_key(&addr, &epk_ct, &r.viewing_key, &*r.master.spending_seed).unwrap();
        let k2 = spend_key(&r.master, &m).unwrap();
        assert_eq!(spend_key_bytes(&k1), spend_key_bytes(&k2));
    }

    #[test]
    fn someone_elses_first_contact_is_false_and_has_no_key() {
        let (us, them) = (ours(), theirs());
        let (addr, epk_ct, _) = generate_stealth_address(&them.meta_bytes).unwrap();
        assert!(
            !check_stealth_address(&addr, &epk_ct, &us.viewing_key, &us.spending_pub_key).unwrap()
        );
        assert!(matches!(
            compute_stealth_key(&addr, &epk_ct, &us.viewing_key, &*us.master.spending_seed),
            Err(Error::MasterKeyMismatch)
        ));
    }

    #[test]
    fn the_address_decides() {
        let r = ours();
        let (mut addr, epk_ct, _) = generate_stealth_address(&r.meta_bytes).unwrap();
        addr[19] ^= 1;
        assert!(
            !check_stealth_address(&addr, &epk_ct, &r.viewing_key, &r.spending_pub_key).unwrap()
        );
        assert!(matches!(
            compute_stealth_key(&addr, &epk_ct, &r.viewing_key, &*r.master.spending_seed),
            Err(Error::MasterKeyMismatch)
        ));
    }

    #[test]
    fn a_memo_or_a_malformed_ephemeral_pub_key_is_false_not_an_error() {
        let r = ours();
        let (addr, epk_ct, _) = generate_stealth_address(&r.meta_bytes).unwrap();
        for bad in [
            Vec::new(),
            epk_ct[..33].to_vec(),
            epk_ct[..1120].to_vec(),
            [epk_ct.as_slice(), &[0]].concat(),
            [&[0x05][..], &epk_ct[1..]].concat(),
        ] {
            assert!(
                !check_stealth_address(&addr, &bad, &r.viewing_key, &r.spending_pub_key).unwrap(),
                "{} bytes",
                bad.len()
            );
            assert!(matches!(
                compute_stealth_key(&addr, &bad, &r.viewing_key, &*r.master.spending_seed),
                Err(Error::Malformed)
            ));
        }
    }

    #[test]
    fn a_malformed_key_of_the_callers_is_an_error() {
        let r = ours();
        let (addr, epk_ct, _) = generate_stealth_address(&r.meta_bytes).unwrap();
        assert!(matches!(
            check_stealth_address(&addr, &epk_ct, &r.viewing_key[..95], &r.spending_pub_key),
            Err(Error::Malformed)
        ));
        let mut zero_viewing = r.viewing_key.clone();
        zero_viewing[..32].fill(0);
        assert!(matches!(
            check_stealth_address(&addr, &epk_ct, &zero_viewing, &r.spending_pub_key),
            Err(Error::NoValidScalar)
        ));
        let mut compact = r.spending_pub_key.clone();
        compact[0] = 0x05;
        assert!(matches!(
            check_stealth_address(&addr, &epk_ct, &r.viewing_key, &compact),
            Err(Error::Malformed)
        ));
        assert!(matches!(
            compute_stealth_key(&addr, &epk_ct, &r.viewing_key, &[0u8; 32]),
            Err(Error::NoValidScalar)
        ));
        assert!(matches!(
            compute_stealth_key(&addr, &epk_ct, &r.viewing_key, &[1u8; 31]),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn generate_rejects_what_decoding_rejects() {
        let r = ours();
        assert!(matches!(
            generate_stealth_address(&r.meta_bytes[..1249]),
            Err(Error::Malformed)
        ));
        let mut compact = r.meta_bytes.clone();
        compact[33] = 0x05;
        assert!(matches!(
            generate_stealth_address(&compact),
            Err(Error::Malformed)
        ));
    }
}
