//! schemeId 5: a pairwise channel. One hybrid ML-KEM-768 + ECDH first contact per
//! sender–recipient pair, then one-byte memos.
//!
//! Specification: `spec/ERC-WWWW-schemeid5.md`. §1 gives the offset, the view tag and the
//! hybrid combiner; §2 the scheme; §3 the wire format.
//!
//! | | first contact | later payments | account |
//! |---|---|---|---|
//! | schemeId 5 | 1 122 B, `epk ‖ ct` + view tag | **1 B**, the view tag | plain EOA |
//!
//! A first contact is ALSO the payment at counter 0, and its own view tag and announced address
//! are what admit the channel (§2.6), so a first payment is one announcement from any account.
//! What the scheme asks for is channel state on both sides.
//!
//! # Role separation
//!
//! §2.7 requires that a scanner's channel state cannot hold a channel opened as a sender: the
//! channel key is symmetric, so a sender's own memos match its own derivation, and a shared
//! list reports the counterparty's funds as the user's own. [`SenderChannel`] and
//! [`ScannerChannel`] are different types with no conversion between them, and the
//! persistence path is role-tagged: each `to_bytes` writes its role first and each
//! `from_bytes` refuses the other role. The tag catches a wrong file being restored; it cannot
//! stop a holder of the secrets from relabelling them on purpose.
//!
//! # Example
//!
//! ```
//! use pqsa_channel::{Announcement, ScannerChannels};
//! use zeroize::Zeroizing;
//!
//! # fn main() -> Result<(), pqsa_core::Error> {
//! // Public example seed.
//! let seed = Zeroizing::new((0u8..128).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect::<Vec<_>>());
//! let (meta, master, tracking) = pqsa_channel::keygen(&seed)?;
//!
//! // Sender: open a channel (paying at counter 0), then pay again with a memo.
//! let (first_contact, mut channel) = pqsa_channel::open_random(&meta)?;
//! let memo = channel.pay()?;
//!
//! // Recipient: bind the tracking key once, then scan.
//! let scanner = pqsa_channel::bind(&tracking, &meta)?;
//! let mut book = ScannerChannels::default();
//! let first = book.scan(&scanner, &Announcement::FirstContact(first_contact)).expect("ours");
//! let second = book.scan(&scanner, &Announcement::Memo(memo)).expect("ours");
//! assert_eq!((first.counter, second.counter), (0, 1));
//!
//! let key = pqsa_channel::spend_key(&master, &second)?;
//! assert_eq!(pqsa_channel::spend_key_bytes(&key).len(), 32);
//! # Ok(())
//! # }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use pqsa_core::{Bytes32, Error, VIEW_TAG_BYTES, reject_if_spending_key_is_delegated};
use pqsa_ec::CompressedPoint;
use pqsa_kem::{Kem, MlKem768};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use zeroize::Zeroizing;

/// The ERC-5564 `schemeId` this crate implements. Not reserved with the ERC-5564 authors.
pub const SCHEME_ID: u64 = 5;

/// Human-readable name, for vectors, test output and the deterministic seed stream. Never
/// parsed, but changing it changes the seeds [`pqsa_core::SenderState`] draws.
pub const NAME: &str = "schemeId 5 (pairwise channel, hybrid)";

/// Keygen seed length: `spending_seed(32) ‖ viewing_ec_seed(32) ‖ kem_seed(64)`. §2.1.
pub const KEYGEN_SEED_BYTES: usize = 128;

/// Seed length for the deterministic [`open`]: `esk(32) ‖ m(32)`. Not from the ERC, which
/// requires CSPRNG randomness (§2.4); [`open_random`] is the sender for real payments.
pub const FIRST_CONTACT_SEED_BYTES: usize = 64;

/// Meta-address length: `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)`. §2.2.
pub const META_ADDRESS_BYTES: usize = 66 + MlKem768::EK_BYTES;

/// A first contact's `ephemeralPubKey`: `epk` (33) then `ct` (1 088). §3.
pub const EPHEMERAL_PUB_KEY_BYTES: usize = 33 + MlKem768::CT_BYTES;

/// Width of the per-payment counter in the payment-secret derivation. It is never published.
/// §2.5. `u128::to_be_bytes` is exactly this encoding.
pub const COUNTER_BYTES: usize = 16;
const _: () = assert!(COUNTER_BYTES == core::mem::size_of::<u128>());

/// §2.6's `SCAN_LOOKAHEAD`: how far above the highest matched counter a scanner tries, and how
/// far below it it still accepts a memo that arrived out of order.
pub const SCAN_LOOKAHEAD: usize = 20;

/// The reference's operational ceiling on a scanner's window. Not normative: §2.6 lets a
/// scanner use a larger window, and this bound only stops a corrupt local record from
/// demanding a huge allocation before any policy sees it.
pub const SCAN_LOOKAHEAD_MAX: usize = 1 << 16;

/// Role tag for persisted SENDER state. §2.7. First byte of [`SenderChannel::to_bytes`].
pub const ROLE_SENDER: u8 = 0x01;
/// Role tag for persisted SCANNER state. §2.7. First byte of [`ScannerChannel::to_bytes`].
pub const ROLE_SCANNER: u8 = 0x02;

/// Offset domain separator. §1.
const DS_OFFSET: &[u8] = b"pq-stealth/offset/v1";
/// View-tag domain separator. §1.
const DS_VIEWTAG: &[u8] = b"pq-stealth/view-tag/v1";
/// The channel-key combiner's domain separator. §1.1, §2.4. Differs from ERC-8441's
/// `"pq-stealth/hybrid-payment/v1"`, so a schemeId 3 payment secret and a schemeId 5 channel
/// key are never derivable from one another, even under one meta-address.
pub const DS_CHANNEL: &[u8] = b"pq-stealth/pairwise/v1";
/// The payment-secret domain separator. §2.5.
pub const DS_PAYMENT: &[u8] = b"pq-stealth/pairwise-payment/v1";

/// Draws before [`open_random`] gives up. A draw is unusable when `esk` or the counter-0
/// offset is out of range, each with probability about 2⁻¹²⁸, so running out means the RNG is
/// broken.
const RANDOM_DRAWS: usize = 64;

/// One-time spending key with redacted `Debug` and cleanup on drop.
pub type SpendKey = SecretBox<Bytes32>;

/// Borrow a [`SpendKey`]'s 32 bytes for a secp256k1 ECDSA signer. Keep the owner alive.
#[must_use]
pub fn spend_key_bytes(k: &SpendKey) -> &[u8] {
    k.expose_secret()
}

// ------------------------------------------------------------------------------------------
// Keys
// ------------------------------------------------------------------------------------------

/// Registry blob: spending point, viewing point, ML-KEM `ek`. §2.2 order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaAddress {
    /// Spending public key every payment address is derived from.
    pub spending: CompressedPoint,
    /// ECDH viewing point a first contact's `ss_ec` is computed against.
    pub viewing_ec: CompressedPoint,
    /// ML-KEM-768 encapsulation key, 1 184 bytes.
    ek: Vec<u8>,
}

impl MetaAddress {
    /// Construct a meta-address, checking the encapsulation-key length. FIPS 203's key check
    /// runs at encapsulation.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `ek` is not [`MlKem768::EK_BYTES`] bytes.
    pub fn new(
        spending: CompressedPoint,
        viewing_ec: CompressedPoint,
        ek: Vec<u8>,
    ) -> Result<Self, Error> {
        if ek.len() != MlKem768::EK_BYTES {
            return Err(Error::Malformed);
        }
        Ok(Self {
            spending,
            viewing_ec,
            ek,
        })
    }

    /// ML-KEM-768 encapsulation-key bytes.
    #[must_use]
    pub fn ek(&self) -> &[u8] {
        &self.ek
    }

    /// The registry encoding, for ERC-6538 `registerKeys(5, meta)`. §2.2.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.spending.as_bytes().as_slice(),
            self.viewing_ec.as_bytes(),
            &self.ek,
        ]
        .concat()
    }

    /// Decode and validate a registry entry: exactly [`META_ADDRESS_BYTES`], both points
    /// compressed `0x02`/`0x03` and on the curve. §2.2.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != META_ADDRESS_BYTES {
            return None;
        }
        Self::new(
            pqsa_ec::decode_point(&bytes[..33]).ok()?,
            pqsa_ec::decode_point(&bytes[33..66]).ok()?,
            bytes[66..].to_vec(),
        )
        .ok()
    }
}

/// Recipient spending secret. Never delegated.
#[derive(Clone)]
pub struct Master {
    /// Scalar every one-time key is offset from.
    pub spending_seed: Zeroizing<Bytes32>,
}

/// Delegatable scan material, `viewing_ec ‖ d ‖ z`. §2.1. A delegated scanner sees every
/// channel and every payment (Security Considerations).
#[derive(Clone)]
pub struct Tracking {
    /// Viewing scalar.
    pub viewing_ec_seed: Zeroizing<Bytes32>,
    /// ML-KEM `(d, z)` seed, 64 bytes. Not the 2 400-byte expanded key.
    pub kem_seed: Zeroizing<Vec<u8>>,
}

impl Tracking {
    /// The 96-byte tracking key, `viewing_ec ‖ d ‖ z`. §2.1, and ERC-5564's `viewingKey`.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new([self.viewing_ec_seed.as_slice(), &self.kem_seed].concat())
    }

    /// Split a 96-byte tracking key. Validity of `viewing_ec` is checked by [`bind`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `bytes` is not 96 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 32 + MlKem768::KEYGEN_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let viewing: Bytes32 = bytes[..32].try_into().map_err(|_| Error::Malformed)?;
        Ok(Self {
            viewing_ec_seed: Zeroizing::new(viewing),
            kem_seed: Zeroizing::new(bytes[32..].to_vec()),
        })
    }
}

/// Derive `(meta, master, tracking)` from a 128-byte seed. Deterministic. §2.1.
///
/// # Errors
///
/// [`Error::Malformed`] on a wrong length; [`Error::NoValidScalar`] if `spending_seed` or
/// `viewing_ec_seed` is not a valid scalar; [`Error::SpendingKeyDelegated`] if
/// `spending_seed` equals `viewing_ec_seed`, `d` or `z`.
pub fn keygen(seed: &[u8]) -> Result<(MetaAddress, Master, Tracking), Error> {
    if seed.len() != KEYGEN_SEED_BYTES {
        return Err(Error::Malformed);
    }
    let spending_seed: &Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
    let viewing_ec_seed: &Bytes32 = seed[32..64].try_into().map_err(|_| Error::Malformed)?;
    reject_if_spending_key_is_delegated(spending_seed, &seed[32..])?;
    let spending = pqsa_ec::public_point(spending_seed)?;
    let viewing_ec = pqsa_ec::public_point(viewing_ec_seed)?;
    let (ek, kem_seed) = MlKem768::keygen(&seed[64..])?;
    Ok((
        MetaAddress::new(spending, viewing_ec, ek)?,
        Master {
            spending_seed: Zeroizing::new(*spending_seed),
        },
        Tracking {
            viewing_ec_seed: Zeroizing::new(*viewing_ec_seed),
            kem_seed,
        },
    ))
}

/// A tracking key checked against a meta-address, plus what scanning reuses.
///
/// Only [`bind`] builds one: §2.6 recommends comparing the recomputed `viewing_ec·G` and `ek`
/// with the registered values before scanning, and here skipping the comparison does not
/// compile. A corrupted `(d, z)` otherwise expands into a valid key pair for a different key
/// and every scan finds nothing, with no error anywhere.
#[derive(Clone)]
pub struct Scanner {
    kem_seed: Zeroizing<Vec<u8>>,
    viewing_ec_seed: Zeroizing<Bytes32>,
    ek: Vec<u8>,
    viewing_pk_ec: CompressedPoint,
    spending: CompressedPoint,
}

/// Recompute `ek` from `(d, z)` and require it equal `registered`. §2.6.
///
/// # Errors
///
/// [`Error::Malformed`] if `kem_seed` has the wrong length;
/// [`Error::TrackingKeyMismatch`] if the recomputed key differs from `registered`.
pub fn verified_ek(kem_seed: &[u8], registered: &[u8]) -> Result<Vec<u8>, Error> {
    let (ek, _) = MlKem768::keygen(kem_seed)?;
    if ek.as_slice() != registered {
        return Err(Error::TrackingKeyMismatch);
    }
    Ok(ek)
}

/// Check `tracking` against `meta` and cache what scanning reuses. §2.6.
///
/// # Errors
///
/// [`Error::TrackingKeyMismatch`] if `viewing_ec·G` or the recomputed `ek` differs from the
/// registered value; [`Error::NoValidScalar`] if `viewing_ec` is not a valid scalar.
pub fn bind(tracking: &Tracking, meta: &MetaAddress) -> Result<Scanner, Error> {
    let viewing_pk_ec = pqsa_ec::public_point(&tracking.viewing_ec_seed)?;
    if viewing_pk_ec != meta.viewing_ec {
        return Err(Error::TrackingKeyMismatch);
    }
    Ok(Scanner {
        ek: verified_ek(&tracking.kem_seed, &meta.ek)?,
        kem_seed: tracking.kem_seed.clone(),
        viewing_ec_seed: tracking.viewing_ec_seed.clone(),
        viewing_pk_ec,
        spending: meta.spending,
    })
}

/// A scanner built from a bare 96-byte `viewingKey` and a spending point, with nothing to
/// compare the recomputed values against. ERC-5564's stateless methods only (§2.10).
fn scanner_unchecked(viewing_key: &[u8], spending: CompressedPoint) -> Result<Scanner, Error> {
    let tracking = Tracking::from_bytes(viewing_key)?;
    let viewing_pk_ec = pqsa_ec::public_point(&tracking.viewing_ec_seed)?;
    let (ek, kem_seed) = MlKem768::keygen(&tracking.kem_seed)?;
    Ok(Scanner {
        kem_seed,
        viewing_ec_seed: tracking.viewing_ec_seed,
        ek,
        viewing_pk_ec,
        spending,
    })
}

// ------------------------------------------------------------------------------------------
// §1: offset, view tag, combiner. §2.5: payment secret.
// ------------------------------------------------------------------------------------------

/// `SHA256(DS_viewtag ‖ ss)[0]`. Does not compute the offset. §1.
#[must_use]
pub fn view_tag_of(ss: &Bytes32) -> [u8; VIEW_TAG_BYTES] {
    let mut h = Sha256::new();
    h.update(DS_VIEWTAG);
    h.update(ss);
    let digest = Zeroizing::new(h.finalize());
    let mut tag = [0u8; VIEW_TAG_BYTES];
    tag.copy_from_slice(&digest[..VIEW_TAG_BYTES]);
    tag
}

/// `H(ss)`: `SHA256(DS_offset ‖ ss)` read big-endian, if `0 < base < n`. §1.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if `base` is 0 or at least `n` (probability about 2⁻¹²⁸). Nothing
/// is reduced mod `n` and nothing is retried.
pub fn offset_of(ss: &Bytes32) -> Result<Zeroizing<Bytes32>, Error> {
    let mut h = Sha256::new();
    h.update(DS_OFFSET);
    h.update(ss);
    let digest = Zeroizing::new(h.finalize());
    let mut base = Zeroizing::new([0u8; 32]);
    base.copy_from_slice(&digest);
    pqsa_ec::validate_scalar(&base)?;
    Ok(base)
}

/// `hybrid_combine(DS, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)` =
/// `SHA3-256(DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek)`. §1.1.
///
/// # Errors
///
/// [`Error::Malformed`] if `ct` or `ek` has the wrong length.
pub fn hybrid_combine(
    domain_separator: &[u8],
    ss_ec: &Bytes32,
    ss_pq: &Bytes32,
    epk: &CompressedPoint,
    ct: &[u8],
    viewing_pk_ec: &CompressedPoint,
    ek: &[u8],
) -> Result<Zeroizing<Bytes32>, Error> {
    if ct.len() != MlKem768::CT_BYTES || ek.len() != MlKem768::EK_BYTES {
        return Err(Error::Malformed);
    }
    let mut h = Sha3_256::new();
    h.update(domain_separator);
    h.update(ss_ec);
    h.update(ss_pq);
    h.update(epk.as_bytes());
    h.update(ct);
    h.update(viewing_pk_ec.as_bytes());
    h.update(ek);
    let digest = Zeroizing::new(h.finalize());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    Ok(out)
}

/// The channel key, `hybrid_combine("pq-stealth/pairwise/v1", …)`. §2.4.
///
/// # Errors
///
/// [`Error::Malformed`] if `ct` or `ek` has the wrong length.
pub fn channel_key(
    ss_ec: &Bytes32,
    ss_pq: &Bytes32,
    epk: &CompressedPoint,
    ct: &[u8],
    viewing_pk_ec: &CompressedPoint,
    ek: &[u8],
) -> Result<Zeroizing<Bytes32>, Error> {
    hybrid_combine(DS_CHANNEL, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
}

/// `ss_i = SHA256("pq-stealth/pairwise-payment/v1" ‖ k_pairwise ‖ u128be(i))`. §2.5.
///
/// Counter 0 is the first contact's payment. The counter is derived on both sides and never
/// published.
#[must_use]
pub fn payment_secret(k_pairwise: &Bytes32, counter: u128) -> Zeroizing<Bytes32> {
    let mut h = Sha256::new();
    h.update(DS_PAYMENT);
    h.update(k_pairwise);
    h.update(counter.to_be_bytes());
    let digest = Zeroizing::new(h.finalize());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    out
}

/// `spending_pk + H(ss)·G` and its address. §1.
fn stealth_address_of(spending: &CompressedPoint, ss: &Bytes32) -> Result<[u8; 20], Error> {
    let offset = offset_of(ss)?;
    let offset_point = pqsa_ec::public_point(&offset)?;
    let stealth = pqsa_ec::add_points(spending, &offset_point)?;
    Ok(pqsa_ec::address_of(&stealth))
}

/// The view tag and address of the payment at `counter`. §2.5.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if `H(ss_counter)` fails its range check.
pub fn payment_at(
    k_pairwise: &Bytes32,
    counter: u128,
    spending: &CompressedPoint,
) -> Result<([u8; VIEW_TAG_BYTES], [u8; 20]), Error> {
    let ss = payment_secret(k_pairwise, counter);
    Ok((view_tag_of(&ss), stealth_address_of(spending, &ss)?))
}

// ------------------------------------------------------------------------------------------
// Wire format, §3
// ------------------------------------------------------------------------------------------

/// A first contact: the channel opening, which is also the payment at counter 0. §2.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstContact {
    /// The sender's ephemeral point.
    pub epk: CompressedPoint,
    /// ML-KEM ciphertext, 1 088 bytes.
    ct: Vec<u8>,
    /// `metadata[0]`: the view tag of the payment at counter 0.
    pub view_tag: [u8; VIEW_TAG_BYTES],
    /// ERC-5564 `stealthAddress`: the address of the payment at counter 0.
    pub stealth_address: [u8; 20],
}

impl FirstContact {
    /// Construct a first contact, checking the ciphertext length.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `ct` is not [`MlKem768::CT_BYTES`] bytes.
    pub fn new(
        epk: CompressedPoint,
        ct: Vec<u8>,
        view_tag: [u8; VIEW_TAG_BYTES],
        stealth_address: [u8; 20],
    ) -> Result<Self, Error> {
        if ct.len() != MlKem768::CT_BYTES {
            return Err(Error::Malformed);
        }
        Ok(Self {
            epk,
            ct,
            view_tag,
            stealth_address,
        })
    }

    /// ML-KEM-768 ciphertext bytes.
    #[must_use]
    pub fn ct(&self) -> &[u8] {
        &self.ct
    }
}

/// A later payment on a channel: the view tag and the address, nothing else. §2.5.
///
/// No field carries the counter: both sides derive it, and a scanner finds it by trying the
/// counters of its window (§2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memo {
    /// `metadata[0]`: the view tag of this payment.
    pub view_tag: [u8; VIEW_TAG_BYTES],
    /// ERC-5564 `stealthAddress`: the address this payment derives.
    pub stealth_address: [u8; 20],
}

/// A schemeId 5 announcement, as ERC-5564's `Announcement` event carries it. §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Announcement {
    /// `ephemeralPubKey` = `epk ‖ ct`, 1 121 bytes.
    FirstContact(FirstContact),
    /// `ephemeralPubKey` empty.
    Memo(Memo),
}

impl Announcement {
    /// `(stealthAddress, ephemeralPubKey, metadata)` for `announce(5, …)`. `metadata` is the
    /// view tag alone; ERC-5564's token metadata, if any, is the caller's to append.
    #[must_use]
    pub fn to_bytes(&self) -> ([u8; 20], Vec<u8>, Vec<u8>) {
        match self {
            Self::FirstContact(fc) => (
                fc.stealth_address,
                [fc.epk.as_bytes().as_slice(), &fc.ct].concat(),
                fc.view_tag.to_vec(),
            ),
            Self::Memo(m) => (m.stealth_address, Vec::new(), m.view_tag.to_vec()),
        }
    }

    /// Parse ERC-5564 event fields. [`None`] for every shape §2.9 makes a skip: `metadata`
    /// empty, an `ephemeralPubKey` of neither 0 nor 1 121 bytes, or an `epk` that is not a
    /// valid compressed point. Bytes after `metadata[0]` are ignored.
    #[must_use]
    pub fn from_bytes(
        stealth_address: &[u8; 20],
        ephemeral_pub_key: &[u8],
        metadata: &[u8],
    ) -> Option<Self> {
        let view_tag: [u8; VIEW_TAG_BYTES] = metadata.get(..VIEW_TAG_BYTES)?.try_into().ok()?;
        match ephemeral_pub_key.len() {
            0 => Some(Self::Memo(Memo {
                view_tag,
                stealth_address: *stealth_address,
            })),
            EPHEMERAL_PUB_KEY_BYTES => {
                let (epk, ct) = ephemeral_pub_key.split_at(33);
                FirstContact::new(
                    pqsa_ec::decode_point(epk).ok()?,
                    ct.to_vec(),
                    view_tag,
                    *stealth_address,
                )
                .ok()
                .map(Self::FirstContact)
            }
            _ => None,
        }
    }

    /// [`Self::from_bytes`], after checking the event's `schemeId`. Any other `schemeId` is
    /// [`None`]: it is not processed under this scheme's rules (§2.3).
    #[must_use]
    pub fn from_event(
        scheme_id: u64,
        stealth_address: &[u8; 20],
        ephemeral_pub_key: &[u8],
        metadata: &[u8],
    ) -> Option<Self> {
        if scheme_id != SCHEME_ID {
            return None;
        }
        Self::from_bytes(stealth_address, ephemeral_pub_key, metadata)
    }
}

// ------------------------------------------------------------------------------------------
// Sender, §2.4 and §2.5
// ------------------------------------------------------------------------------------------

/// A channel as the SENDER holds it. Cannot be scanned with. §2.7.
#[derive(Clone)]
pub struct SenderChannel {
    k_pairwise: Zeroizing<Bytes32>,
    spending: CompressedPoint,
    /// The next unused counter. Persist it before announcing (§2.5).
    next: u128,
}

impl SenderChannel {
    /// Derive the next payment and consume its counter. §2.5.
    ///
    /// A counter whose offset fails §1's range check is skipped, as §2.5 requires, and the
    /// next one is used.
    ///
    /// # Errors
    ///
    /// [`Error::CounterExhausted`] if the counter would reach 2¹²⁸ − 1.
    pub fn pay(&mut self) -> Result<Memo, Error> {
        loop {
            let counter = self.next;
            if counter == u128::MAX {
                return Err(Error::CounterExhausted);
            }
            self.next = counter + 1;
            match payment_at(&self.k_pairwise, counter, &self.spending) {
                Ok((view_tag, stealth_address)) => {
                    return Ok(Memo {
                        view_tag,
                        stealth_address,
                    });
                }
                Err(Error::NoValidScalar) => continue,
                Err(other) => return Err(other),
            }
        }
    }

    /// The next unused counter.
    #[must_use]
    pub fn next_counter(&self) -> u128 {
        self.next
    }

    /// Persisted form, role tag first. 82 bytes:
    /// `0x01 ‖ k_pairwise(32) ‖ spending(33) ‖ next(16, big-endian)`. Secret.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            [
                &[ROLE_SENDER][..],
                self.k_pairwise.as_slice(),
                self.spending.as_bytes(),
                &self.next.to_be_bytes(),
            ]
            .concat(),
        )
    }

    /// Restore from [`Self::to_bytes`]. A scanner record fails at its first byte (§2.7).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a wrong role or length, an invalid point, or `next = 0`: counter
    /// 0 is the first contact's and is spent when the channel exists.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 82 || bytes[0] != ROLE_SENDER {
            return Err(Error::Malformed);
        }
        let k: Bytes32 = bytes[1..33].try_into().map_err(|_| Error::Malformed)?;
        let spending = pqsa_ec::decode_point(&bytes[33..66])?;
        let next = u128::from_be_bytes(bytes[66..82].try_into().map_err(|_| Error::Malformed)?);
        if next == 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            k_pairwise: Zeroizing::new(k),
            spending,
            next,
        })
    }
}

/// Open a channel to `meta` with randomness from the operating system's CSPRNG: the first
/// contact (the payment at counter 0) and the sender's channel, whose next counter is 1. §2.4.
///
/// This is the sender for real payments. `esk` and ML-KEM's `m` are drawn again if `esk` or
/// the counter-0 offset is out of range.
///
/// # Errors
///
/// [`Error::Kem`] if `ek` fails FIPS 203's encapsulation key check; [`Error::Rng`] if the RNG
/// fails.
pub fn open_random(meta: &MetaAddress) -> Result<(FirstContact, SenderChannel), Error> {
    let mut esk = Zeroizing::new([0u8; 32]);
    for _ in 0..RANDOM_DRAWS {
        pqsa_core::os_random(esk.as_mut())?;
        let epk = match pqsa_ec::public_point(&esk) {
            Ok(epk) => epk,
            Err(Error::NoValidScalar) => continue,
            Err(other) => return Err(other),
        };
        match finish_open(meta, &esk, epk, MlKem768::encapsulate_random) {
            Err(Error::SeedRejected) => continue,
            other => return other,
        }
    }
    Err(Error::Rng)
}

/// Open a channel with the randomness fixed by `seed` = `esk(32) ‖ m(32)`. Deterministic.
///
/// For test vectors and reproducible fixtures. Real payments use [`open_random`]: §2.4
/// requires CSPRNG randomness, and the same seed twice opens the same channel to the same
/// recipient, which links and merges every payment on both.
///
/// # Errors
///
/// [`Error::Malformed`] on a wrong seed length; [`Error::SeedRejected`] if `esk` or the
/// counter-0 offset is out of range (draw again); [`Error::Kem`] if `ek` fails FIPS 203's
/// encapsulation key check.
pub fn open(meta: &MetaAddress, seed: &[u8]) -> Result<(FirstContact, SenderChannel), Error> {
    if seed.len() != FIRST_CONTACT_SEED_BYTES {
        return Err(Error::Malformed);
    }
    let esk: &Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
    let epk = pqsa_ec::public_point(esk).map_err(|e| match e {
        Error::NoValidScalar => Error::SeedRejected,
        other => other,
    })?;
    finish_open(meta, esk, epk, |ek| MlKem768::encapsulate(ek, &seed[32..]))
}

/// §2.4 once `esk` is chosen: ECDH, encapsulation, the channel key, the payment at counter 0.
fn finish_open(
    meta: &MetaAddress,
    esk: &Bytes32,
    epk: CompressedPoint,
    encapsulate: impl FnOnce(&[u8]) -> Result<(Vec<u8>, Zeroizing<Bytes32>), Error>,
) -> Result<(FirstContact, SenderChannel), Error> {
    let ss_ec = pqsa_ec::ecdh(esk, &meta.viewing_ec)?;
    let (ct, ss_pq) = encapsulate(&meta.ek)?;
    let k_pairwise = channel_key(&ss_ec, &ss_pq, &epk, &ct, &meta.viewing_ec, &meta.ek)?;
    // An out-of-range counter-0 offset rejects this randomness, not the meta-address. §2.4.
    let (view_tag, stealth_address) =
        payment_at(&k_pairwise, 0, &meta.spending).map_err(|e| match e {
            Error::NoValidScalar => Error::SeedRejected,
            other => other,
        })?;
    Ok((
        FirstContact::new(epk, ct, view_tag, stealth_address)?,
        SenderChannel {
            k_pairwise,
            spending: meta.spending,
            next: 1,
        },
    ))
}

// ------------------------------------------------------------------------------------------
// Scanner, §2.6 and §2.7
// ------------------------------------------------------------------------------------------

/// A matched payment: which channel, which counter, what address, under what secret.
#[derive(Clone)]
pub struct Match {
    /// The derived stealth address, equal to the announced one: the comparison decides (§2.6).
    pub stealth_address: [u8; 20],
    /// The payment secret `ss_i`, for the one-time key.
    pub shared_secret: Zeroizing<Bytes32>,
    /// Which payment: 0 is the first contact, memos are 1 or more.
    pub counter: u128,
    /// The channel the payment is on. As secret as the channel: it derives every payment on it.
    pub channel_key: Zeroizing<Bytes32>,
}

/// The channel key a first contact carries for this scanner, and the counter-0 match if the
/// first contact is addressed to it. §2.6: the view tag first, then the address decides.
fn first_contact_match(scanner: &Scanner, fc: &FirstContact) -> Option<Match> {
    let ss_ec = pqsa_ec::ecdh(&scanner.viewing_ec_seed, &fc.epk).ok()?;
    let ss_pq = MlKem768::decapsulate(&scanner.kem_seed, &fc.ct).ok()?;
    let k_pairwise = channel_key(
        &ss_ec,
        &ss_pq,
        &fc.epk,
        &fc.ct,
        &scanner.viewing_pk_ec,
        &scanner.ek,
    )
    .ok()?;
    counter_zero_match(k_pairwise, &scanner.spending, fc)
}

/// §2.6 from the channel key on: the view tag of `ss_0`, then its address, against the first
/// contact's. Split out so the vectors whose KEM key exists only in expanded form can start
/// from a given `ss_pq`.
fn counter_zero_match(
    k_pairwise: Zeroizing<Bytes32>,
    spending: &CompressedPoint,
    fc: &FirstContact,
) -> Option<Match> {
    let ss_0 = payment_secret(&k_pairwise, 0);
    if view_tag_of(&ss_0) != fc.view_tag {
        return None;
    }
    let stealth_address = stealth_address_of(spending, &ss_0).ok()?;
    if stealth_address != fc.stealth_address {
        return None;
    }
    Some(Match {
        stealth_address,
        shared_secret: ss_0,
        counter: 0,
        channel_key: k_pairwise,
    })
}

/// A channel as the SCANNER holds it. Cannot be paid from. §2.6, §2.7.
///
/// It keeps the highest matched counter `high` (0 after the first contact) and the counters it
/// has matched in `(high − L, high]`, where `L` is its lookahead. A memo is tried at every
/// counter `c ≥ 1` with `high − L < c ≤ high + L` that it has not matched: above `high` for
/// the sender's next payments, below it for a memo included out of order.
#[derive(Clone)]
pub struct ScannerChannel {
    k_pairwise: Zeroizing<Bytes32>,
    spending: CompressedPoint,
    high: u128,
    matched: BTreeSet<u128>,
    lookahead: usize,
    /// Expected view tag → candidate counters, rebuilt when the window moves. Two hashes per
    /// counter; the address is derived only on a tag hit.
    window: BTreeMap<u8, Vec<u128>>,
}

impl ScannerChannel {
    fn new(
        k_pairwise: Zeroizing<Bytes32>,
        spending: CompressedPoint,
        high: u128,
        matched: BTreeSet<u128>,
        lookahead: usize,
    ) -> Result<Self, Error> {
        if !(1..=SCAN_LOOKAHEAD_MAX).contains(&lookahead) {
            return Err(Error::Malformed);
        }
        let mut ch = Self {
            k_pairwise,
            spending,
            high,
            matched,
            lookahead,
            window: BTreeMap::new(),
        };
        ch.rebuild();
        Ok(ch)
    }

    /// The lowest counter still inside the band below `high`.
    fn floor(&self) -> u128 {
        self.high.saturating_sub(self.lookahead as u128 - 1)
    }

    fn rebuild(&mut self) {
        let floor = self.floor();
        self.matched.retain(|&c| c >= floor);
        let top = self
            .high
            .saturating_add(self.lookahead as u128)
            .min(u128::MAX - 1);
        let mut window: BTreeMap<u8, Vec<u128>> = BTreeMap::new();
        let mut c = floor.max(1);
        while c <= top {
            if !self.matched.contains(&c) {
                let tag = view_tag_of(&payment_secret(&self.k_pairwise, c));
                window.entry(tag[0]).or_default().push(c);
            }
            c += 1;
        }
        self.window = window;
    }

    /// The match this memo would be on this channel, without changing anything.
    fn probe(&self, memo: &Memo) -> Option<Match> {
        for &counter in self.window.get(&memo.view_tag[0])? {
            let ss = payment_secret(&self.k_pairwise, counter);
            let Ok(address) = stealth_address_of(&self.spending, &ss) else {
                continue;
            };
            if address == memo.stealth_address {
                return Some(Match {
                    stealth_address: address,
                    shared_secret: ss,
                    counter,
                    channel_key: self.k_pairwise.clone(),
                });
            }
        }
        None
    }

    fn commit(&mut self, counter: u128) {
        self.matched.insert(counter);
        if counter > self.high {
            self.high = counter;
        }
        self.rebuild();
    }

    /// Match a memo against this channel. A hit records the counter and moves the window; a
    /// miss changes nothing.
    pub fn match_memo(&mut self, memo: &Memo) -> Option<Match> {
        let m = self.probe(memo)?;
        self.commit(m.counter);
        Some(m)
    }

    /// The highest counter matched on this channel. 0 until a memo matches.
    #[must_use]
    pub fn highest_counter(&self) -> u128 {
        self.high
    }

    /// The channel key. Secret.
    #[must_use]
    pub fn key(&self) -> &Bytes32 {
        &self.k_pairwise
    }

    /// Persisted form, role tag first:
    /// `0x02 ‖ k_pairwise(32) ‖ spending(33) ‖ high(16) ‖ lookahead(4) ‖ bitmap`, where the
    /// bitmap has `ceil(lookahead / 8)` bytes and bit `j` (byte `j / 8`, bit `j % 8`) records
    /// whether counter `high − j` is matched. Secret.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let lookahead = u32::try_from(self.lookahead).expect("bounded by new()");
        let mut bitmap = vec![0u8; self.lookahead.div_ceil(8)];
        for j in 0..self.lookahead {
            let Some(c) = self.high.checked_sub(j as u128) else {
                break;
            };
            if self.matched.contains(&c) {
                bitmap[j / 8] |= 1 << (j % 8);
            }
        }
        Zeroizing::new(
            [
                &[ROLE_SCANNER][..],
                self.k_pairwise.as_slice(),
                self.spending.as_bytes(),
                &self.high.to_be_bytes(),
                &lookahead.to_be_bytes(),
                &bitmap,
            ]
            .concat(),
        )
    }

    /// Restore from [`Self::to_bytes`]. A sender record fails at its first byte (§2.7).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a wrong role or length, an invalid point, a lookahead outside
    /// `1..=`[`SCAN_LOOKAHEAD_MAX`] (checked before anything is allocated), or a bitmap that
    /// does not mark `high` matched or marks a counter below 0.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 86 || bytes[0] != ROLE_SCANNER {
            return Err(Error::Malformed);
        }
        let k: Bytes32 = bytes[1..33].try_into().map_err(|_| Error::Malformed)?;
        let spending = pqsa_ec::decode_point(&bytes[33..66])?;
        let high = u128::from_be_bytes(bytes[66..82].try_into().map_err(|_| Error::Malformed)?);
        let lookahead =
            u32::from_be_bytes(bytes[82..86].try_into().map_err(|_| Error::Malformed)?) as usize;
        if !(1..=SCAN_LOOKAHEAD_MAX).contains(&lookahead)
            || bytes.len() != 86 + lookahead.div_ceil(8)
        {
            return Err(Error::Malformed);
        }
        let bitmap = &bytes[86..];
        let mut matched = BTreeSet::new();
        for j in 0..bitmap.len() * 8 {
            if bitmap[j / 8] & (1 << (j % 8)) == 0 {
                continue;
            }
            match high.checked_sub(j as u128) {
                Some(c) if j < lookahead => {
                    matched.insert(c);
                }
                _ => return Err(Error::Malformed),
            }
        }
        if !matched.contains(&high) {
            return Err(Error::Malformed);
        }
        Self::new(Zeroizing::new(k), spending, high, matched, lookahead)
    }
}

/// A scanner's retained channels, keyed by channel key. §2.6, §2.7.
///
/// Admits a channel only from a first contact whose view tag and announced address match at
/// counter 0, never retains a channel key twice, and reports a replayed first contact as no
/// payment.
#[derive(Clone)]
pub struct ScannerChannels {
    channels: BTreeMap<Bytes32, ScannerChannel>,
    lookahead: usize,
}

impl Default for ScannerChannels {
    fn default() -> Self {
        Self {
            channels: BTreeMap::new(),
            lookahead: SCAN_LOOKAHEAD,
        }
    }
}

impl ScannerChannels {
    /// An empty book whose channels use `lookahead` instead of [`SCAN_LOOKAHEAD`]. §2.6 lets a
    /// scanner use a larger window, and §2.7's recovery uses one.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `lookahead` is below [`SCAN_LOOKAHEAD`] or above
    /// [`SCAN_LOOKAHEAD_MAX`].
    pub fn with_lookahead(lookahead: usize) -> Result<Self, Error> {
        if !(SCAN_LOOKAHEAD..=SCAN_LOOKAHEAD_MAX).contains(&lookahead) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            channels: BTreeMap::new(),
            lookahead,
        })
    }

    /// Scan one announcement. Every negative outcome is [`None`] (§2.9).
    pub fn scan(&mut self, scanner: &Scanner, announcement: &Announcement) -> Option<Match> {
        match announcement {
            Announcement::FirstContact(fc) => self.admit(scanner, fc),
            Announcement::Memo(memo) => self.match_memo(memo),
        }
    }

    /// Admit a first contact: derive its channel key, require its view tag and announced
    /// address at counter 0, and retain the channel. Returns the payment at counter 0.
    ///
    /// A first contact whose channel is already retained returns [`None`] and changes nothing:
    /// its payment was reported when the channel was admitted.
    pub fn admit(&mut self, scanner: &Scanner, fc: &FirstContact) -> Option<Match> {
        let m = first_contact_match(scanner, fc)?;
        self.retain(&m.channel_key, scanner.spending).then_some(m)
    }

    /// Retain a channel just admitted at counter 0. `false`, and nothing changed, if the key
    /// is already held.
    fn retain(&mut self, k_pairwise: &Zeroizing<Bytes32>, spending: CompressedPoint) -> bool {
        if self.channels.contains_key(&**k_pairwise) {
            return false;
        }
        let Ok(channel) = ScannerChannel::new(
            k_pairwise.clone(),
            spending,
            0,
            BTreeSet::from([0]),
            self.lookahead,
        ) else {
            return false;
        };
        self.channels.insert(**k_pairwise, channel);
        true
    }

    /// Match a memo against every retained channel. The derived address must equal the
    /// announced one, so at most one channel and counter can match (a second would be a
    /// 160-bit collision).
    pub fn match_memo(&mut self, memo: &Memo) -> Option<Match> {
        let m = self.channels.values().find_map(|ch| ch.probe(memo))?;
        self.channels.get_mut(&*m.channel_key)?.commit(m.counter);
        Some(m)
    }

    /// Retain a persisted channel. `false`, and nothing changed, if its key is already held.
    pub fn restore(&mut self, channel: ScannerChannel) -> bool {
        if self.channels.contains_key(channel.key()) {
            return false;
        }
        self.channels.insert(*channel.key(), channel);
        true
    }

    /// Stop deriving for a channel and return it, so it can be persisted and resumed (§2.7).
    /// A retired channel MUST NOT be presented to the user as live.
    pub fn retire(&mut self, key: &Bytes32) -> Option<ScannerChannel> {
        self.channels.remove(key)
    }

    /// Every retained channel, for persistence.
    pub fn iter(&self) -> impl Iterator<Item = &ScannerChannel> {
        self.channels.values()
    }

    /// How many channels are retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Whether no channel is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }
}

// ------------------------------------------------------------------------------------------
// Recipient, §2.8
// ------------------------------------------------------------------------------------------

/// `stealth_sk = (spending_sk + H(ss_i)) mod n`, checked against the match's address. §2.8.
///
/// A one-time key and its `ss` together give the master spending key; do not disclose both.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if the derived scalar is invalid; [`Error::MasterKeyMismatch`] if
/// the key does not control the match's address.
pub fn spend_key(master: &Master, m: &Match) -> Result<SpendKey, Error> {
    spend_key_from(&master.spending_seed, &m.shared_secret, &m.stealth_address)
}

fn spend_key_from(
    spending_seed: &Bytes32,
    shared_secret: &Bytes32,
    stealth_address: &[u8; 20],
) -> Result<SpendKey, Error> {
    let offset = offset_of(shared_secret)?;
    let stealth_sk = pqsa_ec::add_scalars(spending_seed, &offset)?;
    let stealth_pk = pqsa_ec::public_point(&stealth_sk)?;
    if pqsa_ec::address_of(&stealth_pk) != *stealth_address {
        return Err(Error::MasterKeyMismatch);
    }
    let mut key = SpendKey::default();
    key.expose_secret_mut().copy_from_slice(stealth_sk.as_ref());
    Ok(key)
}

/// `Debug` that prints secrets as `[REDACTED]`. Wire types keep derived `Debug`.
macro_rules! redacted_debug {
    ($ty:ident, secrets: [$($sf:ident),*], shown: [$($pf:ident),*]) => {
        impl core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut d = f.debug_struct(stringify!($ty));
                $( d.field(stringify!($pf), &self.$pf); )*
                $( d.field(stringify!($sf), &"[REDACTED]"); let _ = &self.$sf; )*
                d.finish()
            }
        }
    };
}

redacted_debug!(Master, secrets: [spending_seed], shown: []);
redacted_debug!(Tracking, secrets: [viewing_ec_seed, kem_seed], shown: []);
redacted_debug!(Scanner, secrets: [kem_seed, viewing_ec_seed], shown: [ek, viewing_pk_ec, spending]);
redacted_debug!(Match, secrets: [shared_secret, channel_key], shown: [stealth_address, counter]);
redacted_debug!(SenderChannel, secrets: [k_pairwise], shown: [spending, next]);
redacted_debug!(ScannerChannel, secrets: [k_pairwise, window], shown: [spending, high, matched, lookahead]);

impl core::fmt::Debug for ScannerChannels {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The map's keys are channel keys, so only the count prints.
        f.debug_struct("ScannerChannels")
            .field("retained", &self.channels.len())
            .field("lookahead", &self.lookahead)
            .finish()
    }
}

pub mod erc5564;

#[cfg(test)]
mod spec_vectors;

#[cfg(test)]
mod tests;
