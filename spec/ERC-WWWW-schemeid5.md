---
eip: WWWW
title: Hybrid post-quantum stealth address channels
description: ERC-5564 schemeId 5, one hybrid ML-KEM-768 and secp256k1 ECDH first contact per sender and recipient, then one-byte memos
author: namnc (@namnc)
discussions-to: <ethereum-magicians thread, to be opened>
status: Draft
type: Standards Track
category: ERC
created: 2026-11-01
requires: 5564, 6538, 8441
---

## Abstract

[ERC-5564](./eip-5564.md) defines stealth addresses and a `schemeId` namespace, and specifies `schemeId` 1, on secp256k1.
[ERC-8441](./eip-8441.md) specifies `schemeId` 3, which announces each payment with a Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) encapsulation, at parameter set ML-KEM-768, combined with a secp256k1 Elliptic-Curve Diffie-Hellman (ECDH) secret.
Each such announcement takes about 1.1 kB.
This ERC specifies `schemeId` 5, where a sender pays this cost once per recipient.
The first payment to a recipient, the first contact, carries the encapsulation and the ECDH key, and both parties derive a channel key from it.
Each later payment to the same recipient, a memo, announces only a one-byte view tag.
As long as ML-KEM-768 holds, an adversary who later gains access to a quantum computer still cannot tell from the public announcement log who was the receiver.

The scheme protects the announcement layer only. Spending stays vulnerable to a quantum attacker.
Each stealth address is still an ordinary externally owned account (EOA) controlled by a secp256k1 key.
It uses the deployed ERC-5564 announcer and [ERC-6538](./eip-6538.md) registry as is,
with no protocol change and no new contract.
In exchange, the sender and the recipient each keep a channel key and a counter per counterparty.

| | schemeId 5 |
|---|---|
| channel key | ML-KEM-768 shared secret combined with a secp256k1 ECDH secret, once per sender and recipient |
| first contact | 1122 B: an ephemeral public key, an ML-KEM ciphertext and a view tag |
| later payments | 1 B: the view tag |
| meta-address | 1250 B, registered once via ERC-6538, encoded as in ERC-8441 |
| spending | secp256k1 Elliptic Curve Digital Signature Algorithm (ECDSA) from a plain EOA |

## Motivation

As defined in ERC-5564,
stealth-address announcements are public, permanent, and centralized in one contract.
Under `schemeId` 1, their privacy relies on secp256k1 ECDH,
so anyone who can later compute discrete logarithms can link every past payment to its recipient.
ERC-8441 moves the announcement layer to a post-quantum key-encapsulation mechanism (KEM).
Each of its announcements carries a 1088-byte ML-KEM ciphertext
and costs about 2.4 times the gas of a classical announcement.

Many payments go to a recipient the sender has paid before, e.g., salaries, subscriptions or regular suppliers.
For these payments the key exchange does not need to be repeated.
After one encapsulation, both parties share a secret,
and each later payment can derive its stealth address from that secret and a counter.
Its announcement then carries only ERC-5564's one-byte view tag,
and costs less gas than a classical announcement.

On the other hand, both parties have to keep state, a channel has no forward secrecy,
and an observer can tell first contacts from memos.
A sender that cannot keep state can use ERC-8441 instead.
This ERC reuses ERC-8441's meta-address, key generation, offset, view tag and combiner,
so a recipient can register one meta-address for both schemes
and a wallet can share most of its implementation between them.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### 1. Common definitions

Notation:

- `a || b` is byte concatenation, and `x[i..j]` is bytes `i` (inclusive) to `j` (exclusive) of `x`.
- `u256be(b)` reads 32 bytes as an unsigned integer, most significant byte first.
`u128be(i)` is the integer `i` as 16 bytes, most significant byte first.
- `n` is the order of the secp256k1 group and `G` is its generator.
A valid scalar is an integer `k` with `0 < k < n`.
A secp256k1 private scalar MUST be encoded as a 32-byte big-endian integer in this range.
- Points use the compressed encoding of Standards for Efficient Cryptography 1 (SEC1): 33 bytes with tag `0x02` or `0x03`,
whereas `uncompressed(P)` is the 65-byte SEC1 form `0x04 || x || y`.
- `ECDH(k, P).x` is the 32-byte big-endian x-coordinate of `k·P`.
- `SHA256` is SHA-256 as specified in Federal Information Processing Standard (FIPS) 180-4,
and `SHA3-256` is SHA3-256 (FIPS 202)
while `keccak256` is Ethereum's original Keccak-256.
- Domain separators are ASCII strings used as written, with no length prefix and no terminator.

ML-KEM-768 is as specified in FIPS 203. We use it as follows:

- Key generation starts from the 64-byte seed `(d, z)`: `(ek, dk) = ML-KEM.KeyGen_internal(d, z)` (FIPS 203 Algorithm 16).
The seed can be stored in place of the decapsulation key and only expanded when needed.
- Encapsulation is FIPS 203 `ML-KEM.Encaps(ek)` (Algorithm 20).
We use the deterministic `ML-KEM.Encaps_internal(ek, m)` (Algorithm 17) only in the test vectors (Test Cases).
- Decapsulation is FIPS 203 `ML-KEM.Decaps(dk, ct)`,
or `ML-KEM.Decaps_internal` on a `dk` expanded from `(d, z)`.
Note that ML-KEM rejects implicitly:
a well-formed ciphertext that was not intended for `dk` decapsulates to a pseudorandom value, not to an error.

**Offset and view tag.** From a 32-byte payment secret `ss` (Section 2.5):

```
base = SHA256("pq-stealth/offset/v1" || ss)
if 0 < u256be(base) < n:  H(ss) = u256be(base)
else:                     fail

view_tag(ss) = SHA256("pq-stealth/view-tag/v1" || ss)[0..1]                   1 B
```

Sender and recipient MUST both run exactly this procedure.
An implementation MUST NOT reduce `base` mod `n` or derive another candidate.
On failure, the sender does not use that payment secret (Sections 2.4 and 2.5),
and a scanner skips the announcement (Section 2.9).
As `base` is out of range with probability below 2^-127,
test vectors reach the failure by supplying `base` directly (Test Cases).

The stealth key pair and its address keep ERC-5564's structure:

```
stealth_pk          = spending_pk + H(ss)·G
stealth_sk          = (spending_sk + H(ss)) mod n
address(stealth_pk) = keccak256(uncompressed(stealth_pk)[1..65])[12..32]
```

These definitions are ERC-8441's, and differ from ERC-5564's `schemeId` 1 in the same four ways:

1. The hashed secret is a payment secret derived from the hybrid channel key (Section 2.5), not the ECDH shared point.
2. ERC-5564's hash function `h` is made explicit SHA-256 under the domain separator `"pq-stealth/offset/v1"`.
3. ERC-5564 takes the view tag from the first byte of the digest that also becomes the scalar.
Here the view tag is a separate digest under its own domain separator.
4. ERC-5564 uses the digest as the scalar with no range check.
Here the range check above yields a valid scalar or fails.

#### 1.1 The hybrid combiner

```
hybrid_combine(DS, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
    = SHA3-256(DS || ss_ec || ss_pq || epk || ct || viewing_pk_ec || ek)               32 B
```

This is ERC-8441's combiner.
`schemeId` 5 uses `DS = "pq-stealth/pairwise/v1"` (22 bytes) and names the output `k_pairwise`, the channel key (Section 2.4).
The domain separator differs from ERC-8441's `"pq-stealth/hybrid-payment/v1"`,
so a `schemeId` 5 channel key and a `schemeId` 3 payment secret are never derivable from one another,
even when both are derived for the same meta-address.

1. `ss_ec` MUST be the 32-byte x-coordinate alone.
2. `epk` and `viewing_pk_ec` MUST be their 33-byte compressed encodings.
`ct` MUST be the 1088-byte ML-KEM ciphertext as announced,
and `ek` the 1184-byte encapsulation key as registered.
3. The input order MUST be exactly as shown,
with `DS` first,
and the output MUST be the full 32-byte digest.

Every field has a fixed length, so plain concatenation encodes the inputs unambiguously.

The combiner has the shape of `KeyCombineCCA_H` in National Institute of Standards and Technology (NIST) Special Publication (SP) 800-227 §4.6.3 (an instance of Eq. (15)):

| SP 800-227 input | here | role |
|---|---|---|
| `K1`, `K2` | `ss_ec`, `ss_pq` | the two shared secrets |
| `c1` | `epk` | the ECDH "ciphertext": the sender's ephemeral public key |
| `c2` | `ct` | the ML-KEM ciphertext |
| `ek1` | `viewing_pk_ec` | the ECDH "encapsulation key": the recipient's viewing key |
| `ek2` | `ek` | the ML-KEM encapsulation key |
| `domain_sep` | `DS` | names this scheme and this combiner |

It departs from the exact shape in three ways:

- `DS` comes first rather than last.
- The inputs are concatenated rather than given as a list.
SP 800-227 §4.6.2 allows plain concatenation when the encoding is unambiguous, as it is here.
- We use a bare hash, not SP 800-56C's one-step key derivation function (KDF), which prefixes a 32-bit counter.

With the hash modelled as a random oracle,
hashing both shared secrets together with both ciphertexts yields a KEM that is indistinguishable under adaptive chosen-ciphertext attack (IND-CCA) if either component KEM is IND-CCA.
Including the two encapsulation keys binds the channel key to the recipient's identity.

### 2. schemeId 5

A sender opens a channel to a recipient with a first contact.
The first contact carries one ML-KEM encapsulation and one ephemeral secp256k1 key,
and is also the first payment on the channel, at counter 0.
Each later payment on the channel, a memo, uses the next counter and carries only its view tag.
Spending stays secp256k1 ECDSA on an ordinary EOA,
so it needs no new verifier and no consensus change.

```
first contact, counter 0:
  sender    : esk, epk    <- a fresh secp256k1 key pair                  (Section 2.4)
              (ct, ss_pq) <- ML-KEM-768.Encaps(ek)
              k_pairwise  <- hybrid_combine(DS, ECDH(esk, viewing_pk_ec).x, ss_pq,
                                            epk, ct, viewing_pk_ec, ek)
              announce(5, address(ss_0), epk || ct, view_tag(ss_0)); pay the address
  scanner   : ss_ec <- ECDH(viewing_ec, epk).x;  ss_pq <- ML-KEM-768.Decaps(dk, ct)
              k_pairwise <- the same hybrid_combine call
              compare the view tag, then the address, of ss_0; retain the channel

memo, counter i = 1, 2, ...:
  sender    : announce(5, address(ss_i), empty, view_tag(ss_i)); pay the address
  scanner   : for each retained channel, compare the view tag, then the address,
              of ss_c for each counter c in the channel's window          (Section 2.6)

where ss_i = SHA256("pq-stealth/pairwise-payment/v1" || k_pairwise || u128be(i))
recipient : stealth_sk = (spending_sk + H(ss_i)) mod n
```

#### 2.1 Keys and seeds

Key generation takes a 128-byte seed and MUST be deterministic:
i.e., the same seed MUST produce the same three outputs.

```
seed     = spending_seed(32) || viewing_ec_seed(32) || kem_seed(64)
kem_seed = d(32) || z(32)
```

An implementation MUST reject a seed of any other length rather than pad or truncate it.

- `spending_seed` is the master spending key `spending_sk`.
It MUST be a valid scalar, and key generation MUST fail otherwise.
- `viewing_ec_seed` is the viewing scalar `viewing_ec`.
It MUST be a valid scalar, and key generation MUST fail otherwise.
- `kem_seed` is ML-KEM's `(d, z)`.
Key generation computes `(ek, dk) = ML-KEM.KeyGen_internal(d, z)`,
and the tracking key is `(d, z)`.

The three components MUST be generated independently of one another.
Each MUST be either drawn from a cryptographically secure random number generator (CSPRNG)
or derived from a master secret by a pseudorandom function (PRF) in a way that gives each component an independent output.
In particular, a wallet MUST NOT use the spending key as the viewing key.
The tracking key is meant to be handed to a scanning service, which is why it cannot be allowed to carry the spending key.
Key generation MUST fail if `spending_seed` equals `viewing_ec_seed`, `d`, or `z`.

Key generation has three outputs:

| output | contents | size | disposition |
|---|---|---|---|
| meta-address | `spending_pk || viewing_pk_ec || ek` | 1250 B | published via ERC-6538 (Section 2.2) |
| master key | `spending_sk` | 32 B | never leaves the owner |
| tracking key | `viewing_ec || d || z` | 96 B | MAY be delegated to a scanning service |

Here `spending_pk = spending_sk·G` and `viewing_pk_ec = viewing_ec·G`.
This is ERC-8441's key generation, so one seed gives the same keys under both schemes.

#### 2.2 Meta-address encoding

```
meta = spending_pk(33) || viewing_pk_ec(33) || ek(1184)                       1250 B
```

A decoder MUST reject any length other than 1250 bytes.
In ERC-5564's text form, a meta-address is `st:eth:0x` followed by the 2500 hex digits of `meta`.
The string does not carry the `schemeId`, so a parser MUST NOT read it as two `schemeId` 1 keys;
its length tells the two forms apart.

Before the meta-address is used for anything,
the decoder MUST check that both 33-byte fields carry tag `0x02` or `0x03`
and decode to points on secp256k1.
It MUST NOT accept other SEC1 forms.
`ek` MUST pass FIPS 203's encapsulation input check (§7.2) before its first use.

#### 2.3 Registration and scheme selection

A recipient MUST register the encoded meta-address with ERC-6538 `registerKeys(5, meta)`.

A recipient MAY register under several `schemeId`s,
and MAY register the same meta-address under `schemeId` 3 and `schemeId` 5:
the two schemes' secrets are domain-separated (Section 1.1).
A scanner MUST process each announcement only under the rules of the `schemeId` it carries,
with the recipient's keys for that `schemeId`.
A recipient who clears a `schemeId` SHOULD keep scanning it for payments made before the change.
A sender MUST treat an empty registry entry as unregistered.

A sender that implements `schemeId` 5 and finds the recipient registered under it
MUST NOT pay that recipient under `schemeId` 1.
If the recipient is registered under both `schemeId` 3 and `schemeId` 5,
a sender that implements both MAY use either.
A sender that cannot keep the channel state of Section 2.5 SHOULD use `schemeId` 3.
A recipient who wants post-quantum announcement privacy SHOULD NOT register under `schemeId` 1,
and SHOULD clear an existing `schemeId` 1 entry by registering an empty value under it.

#### 2.4 First contact

A sender opens a channel to a recipient with a first contact, which is also the payment at counter 0.

Each first contact needs a fresh ephemeral scalar `esk` and fresh encapsulation randomness.
Reusing `esk` repeats `epk`, which links the two first contacts to one sender.
Reusing both against the same recipient repeats the channel key,
and with it every stealth address on the channel.

A sender MUST draw this randomness from a cryptographically secure random number generator.
For `esk` it draws 32 bytes, and if they are not a valid scalar, discards them and draws again.
For the encapsulation it calls `ML-KEM.Encaps(ek)`,
whose randomness FIPS 203 §3.3 requires to come from an approved random bit generator (RBG)
with a security strength of at least 192 bits for ML-KEM-768.
If `H(ss_0)` below fails (Section 1), the sender discards both and draws again.

The sender then computes:

```
epk         = SEC1-compressed(esk·G)                                          33 B
ss_ec       = ECDH(esk, viewing_pk_ec).x                                      32 B
(ct, ss_pq) = ML-KEM-768.Encaps(ek)                                 1088 B / 32 B
k_pairwise  = hybrid_combine("pq-stealth/pairwise/v1",
                             ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)        32 B
ss_0        = SHA256("pq-stealth/pairwise-payment/v1" || k_pairwise
                     || u128be(0))                                            32 B
stealth_pk  = spending_pk + H(ss_0)·G                                  (Section 1)
address     = keccak256(uncompressed(stealth_pk)[1..65])[12..32]              20 B
```

It calls ERC-5564 `announce(5, address, epk || ct, view_tag(ss_0))` (Section 3)
and pays `address`.
The `stealthAddress` argument MUST be `address`,
because scanners compare against it.
The sender MAY append ERC-5564's token metadata after the view tag.
It then keeps the channel: `k_pairwise`, the recipient's `spending_pk`, and the next counter, 1 (Section 2.5).

A sender MAY open more than one channel to the same recipient.
If it may have lost the state of a channel, it SHOULD open a new one.

#### 2.5 Later payments

The payment at counter `i` on a channel uses the payment secret

```
ss_i = SHA256("pq-stealth/pairwise-payment/v1" || k_pairwise || u128be(i))    32 B
```

Counter 0 is the first contact (Section 2.4).
Each later payment, a memo, uses the channel's next unused counter `i ≥ 1`
and derives its stealth key pair and address from `ss_i` as in Section 1.
The sender calls ERC-5564 `announce(5, address, ephemeralPubKey, view_tag(ss_i))`
with an empty `ephemeralPubKey`, and pays `address`.
The `stealthAddress` argument MUST be `address`.
The sender MAY append ERC-5564's token metadata after the view tag.

The counter is derived on both sides and MUST NOT be published.
Both parties MUST encode it exactly as `u128be`,
since a different width or byte order derives a different payment secret.

The counter is per channel.
A sender MUST use each counter of a channel at most once, in increasing order:
a repeated counter repeats the stealth address, which links the two payments on chain and merges them onto one key.
A sender MUST persist the next unused counter before it announces the payment that uses it,
so that a crash cannot lead it to reuse a counter.
A counter persisted but never announced leaves a gap, which a scanner's window absorbs (Section 2.6).
If `H(ss_i)` fails (Section 1), the sender skips counter `i` and uses `i + 1`.
A counter MUST be less than 2^128 - 1, so that the next counter still fits in 16 bytes.

A sender that loses its channel state SHOULD open a new channel (Section 2.4).
A sender SHOULD also open a new channel after a long period without payments,
since a recipient MAY stop scanning an idle channel (Section 2.7).

#### 2.6 Scanner

Given a tracking key `viewing_ec || d || z` and the recipient's meta-address,
a scanner processes each announcement under `schemeId` 5 whose fields have the lengths of Section 3.
A 1121-byte `ephemeralPubKey` is a first contact, and an empty one is a memo.

Before scanning, a scanner SHOULD recompute `viewing_ec·G` and `ek` from the tracking key
and compare them with the registered values.
Otherwise a corrupted tracking key fails silently.

**First contacts.**

```
epk        <- ephemeralPubKey[0..33]
ct         <- ephemeralPubKey[33..1121]
ss_ec      <- ECDH(viewing_ec, epk).x
ss_pq      <- ML-KEM-768.Decaps(dk, ct)                  dk expanded from (d, z)
k_pairwise <- hybrid_combine("pq-stealth/pairwise/v1",
                             ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
ss_0       <- SHA256("pq-stealth/pairwise-payment/v1" || k_pairwise || u128be(0))
if view_tag(ss_0) != metadata[0]:               skip
stealth_pk <- spending_pk + H(ss_0)·G
if address(stealth_pk) != stealthAddress:       skip
match (stealthAddress, ss_0), and retain the channel k_pairwise   (Section 2.7)
```

The combiner takes `viewing_pk_ec` and `ek` from the registered meta-address.
A matched first contact is a payment, at counter 0.
A scanner MUST report it as one,
in addition to retaining the channel;
otherwise the first payment on every channel is lost.

**Memos.** For each retained channel, a scanner keeps `h`, the highest counter it has matched on the channel (0 after the first contact),
and which counters in `(h - SCAN_LOOKAHEAD, h]` it has matched.
The channel's window is every counter `c` with

```
c ≥ 1,   h - SCAN_LOOKAHEAD < c ≤ h + SCAN_LOOKAHEAD,   and c not yet matched
SCAN_LOOKAHEAD = 20
```

A memo matches a channel at counter `c` in its window if

```
view_tag(ss_c) == metadata[0]   and   address(spending_pk + H(ss_c)·G) == stealthAddress
```

and a scanner MUST NOT report a memo that matches no channel.
On a match the scanner reports the payment `(stealthAddress, ss_c)`, records `c` as matched,
and sets `h` to `c` if `c` is greater.
A scanner MUST try every counter in the window of every retained channel,
and MAY try more: a larger `SCAN_LOOKAHEAD`, or counters below the window.
The counters above `h` absorb gaps the sender left (Section 2.5),
and those below `h` find memos included out of order.

The view tag depends only on the channel key and the counter,
so a scanner MAY derive each channel's window of view tags once
and look each memo's `metadata[0]` up in it.
A memo then costs one lookup per channel,
plus an address derivation for each window entry whose tag matches, about 1 in 256.

**First contacts and memos.** The address comparison decides correctness of matching.
The one-byte view tag only lets a scanner skip the offset,
the point arithmetic and the address hash for 255 of 256 candidates.
Decapsulation never fails, so a scanner MUST NOT treat a successful decapsulation as a match,
and MUST NOT retain a channel on a successful decapsulation.

The view tag of a first contact is a function of `k_pairwise`,
so it cannot be checked before both the ECDH and the decapsulation.
Every `schemeId` 5 first contact therefore costs a scanner
at least one ECDH and one ML-KEM-768 decapsulation.
A memo costs no public-key operation unless a view tag matches.

`announce()` is permissionless, so anyone can replay a real announcement.
A scanner SHOULD deduplicate matches by stealth address.

#### 2.7 Channel state

**Retention.** A scanner retains a channel only from a first contact that matched (Section 2.6).
A scanner MUST NOT retain a channel key it already holds.
A first contact whose channel is already retained is a replay:
the scanner MUST NOT report its counter-0 payment a second time,
and MUST NOT reset the channel's `h` or matched counters.

**Roles.** The channel key is symmetric,
so a sender's own memos match the sender's own derivation.
A wallet that both sends and receives MUST keep the channels it opened as a sender
apart from the channels it retained as a scanner,
and MUST NOT match announcements against channels it opened as a sender.
Otherwise it reports a payment it made to a counterparty as a payment it received.
Persisted channel state SHOULD record which of the two roles it belongs to,
and an implementation MUST NOT restore it into the other role.

**Idle channels.** A scanner MAY stop deriving the window of a channel that has had no memo for a period of its choosing.
A scanner that does so MUST NOT present the channel to its user as live,
and SHOULD keep enough to resume it, such as the channel key and `h`.
Resuming then only needs a rescan of that channel's memos since it was retired.
This ERC does not specify the period.

**Recovery.** Channel state is derivable from the chain.
A recipient who has lost it SHOULD rebuild it by scanning every `schemeId` 5 first contact (Section 2.6)
and then every memo against the channels retained,
in block order, with the window of Section 2.6.
A recovering scanner MAY use a larger `SCAN_LOOKAHEAD`.
Every first contact can be tested on its own bytes,
so recovery costs one ECDH and one decapsulation per first contact, and a window lookup per memo per channel.

#### 2.8 Recipient

```
stealth_sk = (spending_sk + H(ss_i)) mod n
```

The recipient SHOULD check that `stealth_sk·G` gives the matched address before using the key.

A one-time key and its `ss_i` together give the master spending key:
`spending_sk = (stealth_sk - H(ss_i)) mod n`.
Implementations MUST NOT disclose both for the same payment.
A channel key gives every `ss_i` on its channel,
so implementations MUST NOT disclose a channel key together with any one-time key from that channel.
A scanning service already holds every channel key,
so handing it any one-time key hands it the master key.

#### 2.9 Errors and skips

| condition | behaviour |
|---|---|
| `schemeId` other than 5 | not processed under this scheme's rules (Section 2.3) |
| `metadata` empty | skip |
| `ephemeralPubKey` neither 0 nor 1121 bytes | skip |
| `epk` not a valid compressed point | skip |
| view tag mismatch | skip |
| `H(ss_i)` fails its range check (Section 1) | skip |
| announced `stealthAddress` differs from the derived address | skip, and a first contact is not retained |
| first contact for a channel already retained | skip, with no payment reported (Section 2.7) |
| memo matching no counter in any retained channel's window | skip |
| decapsulation "fails" | cannot happen, because the 1121-byte check fixes `ct` at 1088 bytes, `dk` is expanded from the scanner's own `(d, z)`, and ML-KEM rejects implicitly |
| keygen seed not 128 bytes | error, at key generation |
| `spending_seed` or `viewing_ec_seed` not a valid scalar | error, at key generation |
| `spending_seed` equal to `viewing_ec_seed`, `d` or `z` | error, at key generation |
| meta-address not 1250 bytes, or either point invalid | error, at decoding |
| `ek` fails FIPS 203's encapsulation input check | error, at encapsulation |
| a sender's counter would repeat or reach 2^128 - 1 | error, at the sender |
| `viewingKey`, `spendingPubKey` or `spendingKey` malformed (Section 2.10) | error |

A memo that matches no window can be a payment to someone else,
a payment from a sender that skipped past the window, or a payment on a channel the scanner retired.
A scanner cannot tell these apart, so it skips the memo.

#### 2.10 ERC-5564 methods

Per ERC-5564 our scheme also defines `generateStealthAddress`, `checkStealthAddress` and `computeStealthKey`.
`schemeId` 5 uses ERC-5564's signatures unchanged.
These methods are stateless, and a memo can only be checked with the channel state created by its first contact.
Hence the methods apply to first contacts only, and memos are scanned as described in Section 2.6.

- `generateStealthAddress(stealthMetaAddress)` implements Section 2.4 and returns `address`,
  `epk || ct` as `ephemeralPubKey`, and `view_tag(ss_0)` as `viewTag`.
  `stealthMetaAddress` is the 1250-byte `meta` of Section 2.2.
  It returns no channel key, so the channel it opens carries no later payment.
  A sender that keeps the channel implements Section 2.4 directly.
- `checkStealthAddress(stealthAddress, ephemeralPubKey, viewingKey, spendingPubKey)` derives `ss_0`
  and compares the derived address with `stealthAddress` (Section 2.6).
  For well-formed caller keys, it returns `false` for an empty `ephemeralPubKey`,
  any other malformed `ephemeralPubKey`, an invalid offset or stealth public key, or an address mismatch.
  It receives neither `schemeId` nor `metadata`; a scanner checks those separately.
- `computeStealthKey(stealthAddress, ephemeralPubKey, viewingKey, spendingKey)` implements Section 2.8 for counter 0.
- `viewingKey` is the 96-byte tracking key, from which `viewing_pk_ec` and `ek` are recomputed.
  `spendingPubKey` is `spending_pk`, and `spendingKey` is `spending_sk`.

`viewingKey`, `spendingPubKey` and `spendingKey` are the caller's own keys, not announcement data.
`checkStealthAddress` and `computeStealthKey` fail, rather than return `false`,
when `viewingKey` is not 96 bytes or its `viewing_ec` is not a valid scalar,
when `spendingPubKey` is not a valid compressed point (Section 2.2),
or when `spendingKey` is not a valid scalar.
Returning `false` would turn a broken key into a scan that finds nothing.

`computeStealthKey` MUST fail rather than return a key
when `ephemeralPubKey` is not a well-formed first contact
or when `address(stealth_sk·G)` differs from `stealthAddress`.

### 3. Wire format

Announcements use ERC-5564's `announce(schemeId, stealthAddress, ephemeralPubKey, metadata)` unchanged:

| argument | first contact | memo |
|---|---|---|
| `schemeId` | 5 | 5 |
| `stealthAddress` | the address of `ss_0` (Section 2.4), 20 B | the address of `ss_i` (Section 2.5), 20 B |
| `ephemeralPubKey` | `epk || ct`, exactly 1121 B | empty |
| `metadata` | `view_tag(ss_0)`, then optional ERC-5564 token metadata | `view_tag(ss_i)`, then optional ERC-5564 token metadata |

1. A first contact's `ephemeralPubKey` MUST be exactly `epk || ct`, in that order: `epk` in bytes 0 to 32 and
   `ct` in bytes 33 to 1120. A memo's `ephemeralPubKey` MUST be empty.
2. The view tag MUST be the first byte of `metadata`, as ERC-5564 requires.
3. A sender MAY follow the view tag with the 56 bytes of token metadata ERC-5564 recommends.
   `schemeId` 5 gives no meaning to any byte after the first.
   A scanner MUST read only `metadata[0]`,
   and MUST NOT skip an announcement because `metadata` is longer than one byte.
   These bytes are not bound into any secret,
   so, as under `schemeId` 1, they are the sender's unauthenticated claim.
4. The counter appears in no field.

A scanner MUST skip a `schemeId` 5 announcement whose `ephemeralPubKey` is neither 0 nor 1121 bytes
or whose `metadata` is empty (Section 2.9).
Meta-addresses are registered with ERC-6538 `registerKeys(5, meta)` (Section 2.3).

A first contact has the same field lengths as an ERC-8441 `schemeId` 3 announcement.
The `schemeId` tells them apart.

## Rationale

### Why a channel

The ML-KEM ciphertext is the bulk of an ERC-8441 announcement, and a per-payment scheme has to publish it on every payment.
A channel publishes it once per sender and recipient.
After the first contact both parties share `k_pairwise`,
and a pseudorandom function (PRF) over a counter gives each later payment a fresh secret without another public-key operation.
The same construction is used by Bitcoin Improvement Proposal (BIP) 47 reusable payment codes,
which derive many addresses per sender and recipient from one notification and an index,
and by Aztec's tag hopping and Starknet's channels.
It matters more in the post-quantum setting:
ML-KEM has no small ciphertext and no cheap partial check,
so each per-payment announcement costs 1088 bytes to publish and a decapsulation to scan.

### Why the first contact is also a payment

If the first contact only opened the channel, the first payment would need a separate memo,
and a scanner would have to pair the two announcements.
Pairing them inside one transaction needs a sender that can batch calls, which a plain EOA cannot do.
Pairing them across transactions lets an adversary insert a decoy between them.
With the first contact as the payment at counter 0, there is nothing to pair:
the first contact carries its own view tag and stealth address and is checked on its own.
A first payment is then one announcement and one transfer, from any account.

### Why the counter is not on the wire

A counter in each memo would show every observer the position of each payment in its channel,
and the age of a channel from a large counter.
Both sides derive the counter instead, so a memo carries only the view tag.
In turn, a scanner tries a window of counters,
and misses a sender that skips more than `SCAN_LOOKAHEAD` counters until it recovers (Section 2.7).
`SCAN_LOOKAHEAD` is fixed at 20, as BIP 44 fixes its gap limit at 20,
because wallets have to agree on it.
Each counter in a window costs two SHA-256 calls, and a window has at most `2 · SCAN_LOOKAHEAD` counters.

### Why the window extends below the highest matched counter

Memos are separate transactions.
A sender that announces from several accounts, or through a relayer, does not control the order in which they are included.
If the window only covered counters above the highest one matched,
a memo included after a later one would be missed.
The window therefore also covers `SCAN_LOOKAHEAD` counters below it,
and the scanner remembers which of those it has matched, so a replayed memo is not reported twice.

### Why the announced address decides, with a one-byte view tag

A memo carries only the view tag and the announced address, so one of them has to identify the payment.
The address has 20 bytes and is a function of the payment secret, so comparing it is exact.
The view tag can then stay the single byte of ERC-5564,
and ERC-5564's token metadata stays where it is.
A wider tag would let a scanner decide on the tag alone,
but would move the token metadata and add nothing the address comparison does not give.
In turn, a matching tag costs an address derivation, for about 1 in 256 counters in a window.

First contacts are matched the same way.
A channel is retained only when both its view tag and its address match at counter 0.
A first contact addressed to someone else decapsulates to a pseudorandom key without error,
and is therefore not retained.

### Why a hybrid, and why ERC-8441's primitives

ML-KEM is new, and so are its implementations.
With the ECDH half, recovering `k_pairwise` needs both secrets.
Against a classical adversary the channel is as hard to open as today's ECDH,
and against a quantum adversary as hard as ML-KEM-768 alone.
The ECDH half costs 33 bytes per first contact and nothing per memo.

The meta-address, key generation, offset, view tag and combiner are those of ERC-8441, for the reasons given there.
A wallet implements them once, and a recipient registers one meta-address for both schemes.
Only the domain separator of the combiner differs,
so a `schemeId` 3 announcement cannot open a channel,
and a channel key cannot be a `schemeId` 3 payment secret.

### Why the payment secret is SHA-256 of the channel key and counter

After the first contact both parties hold `k_pairwise` and need a PRF over the counter.
SHA-256 under a domain separator, with fixed-length inputs, serves as that PRF,
and it is already used for the offset and the view tag.
The payment secret does not need to bind `ct` or the public keys again,
since `hybrid_combine` binds them into `k_pairwise`.

### Why the sender's randomness is drawn, not derived

The scanner only decapsulates, so the sender's source of randomness does not affect interoperability,
and we can pick the simplest safe source.
Determinism is only needed in the test vectors, to pin `ct`.

### Cost

These are Prague figures:
the `gasUsed` of transactions executed under the Prague hardfork rules.
Both contracts run their canonical deployed runtime bytecode at their mainnet addresses:
the ERC-5564 announcer at `0x55649E01B5Df198D18D95b5cc5051630cfD45564`
and the ERC-6538 registry at `0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538`.
The `schemeId` 5 rows use a real first contact, memo and meta-address.
The `schemeId` 1 rows use constructed payloads of the same lengths with no zero byte.

**Announcement**, a standalone `announce()` call:

| schemeId | `ephemeralPubKey` + `metadata` | calldata | gas | pricing rule | vs classical |
|---|---|---|---|---|---|
| 1 (classical) | 34 B | 292 B | 28313 | standard | 1.00x |
| 5, first contact | 1122 B | 1380 B | 69090 | [EIP-7623](./eip-7623.md) floor | 2.44x |
| 5, first contact with token metadata | 1178 B | 1412 B | 70310 | EIP-7623 floor | 2.48x |
| 5, memo | 1 B | 228 B | 26961 | standard | 0.95x |
| 5, memo with token metadata | 57 B | 260 B | 27793 | standard | 0.98x |

The first-contact receipts equal the EIP-7623 calldata floor exactly: 21000 plus 10 per calldata token.
So execution is not charged, and the figure is set by calldata size alone.
The memo and classical receipts are above their floors and pay the standard rate.
The ratios therefore compare two pricing rules, and any calldata repricing will move them.
A memo costs less than a classical announcement because its empty `ephemeralPubKey`
is two 32-byte words shorter, in calldata and in the event data.

**Registration**, a first-time `registerKeys` call with a fresh registrant:

| schemeId | meta-address | vs schemeId 1's 66 B | gas |
|---|---|---|---|
| 1 (classical) | 66 B | 1.0x | 115310 |
| 5 | 1250 B | 18.9x | 964737 |

ERC-6538 writes the meta-address to contract storage, one slot per 32 bytes.
Storage writes make up most of this cost, and it is paid once per recipient.
A recipient who also registers the same meta-address under `schemeId` 3 pays this amount once for each `schemeId`.

**Payment end to end**, for native ETH only:

| | announce | fund | spend | total gas |
|---|---|---|---|---|
| first payment on a channel | 69090 | 21000 | 21000 | 111090 |
| each later payment | 26961 | 21000 | 21000 | 68961 |

Each measured payment announces, funds the derived address, and spends from it with the derived key.
A token payment adds the token transfer.
Unless the sender sponsors gas, it also needs a transaction that funds the stealth EOA,
which links addresses (Security Considerations).

## Backwards Compatibility

This ERC needs no consensus change, no new opcode and no new contract.
It calls ERC-5564's `announce()` and ERC-6538's `registerKeys` as deployed.
Existing `schemeId` 1 and `schemeId` 3 deployments are unaffected,
and a recipient can register the same meta-address under `schemeId` 3 and `schemeId` 5.
ERC-5564 requires the ERC that standardises a scheme to declare its `schemeId`,
and this ERC declares `schemeId` 5.

`schemeId` 5 departs from ERC-5564's conventions in three ways.
First, as in ERC-8441, its 1250-byte meta-address does not have ERC-5564's length `n` or `2n` for `n`-byte keys.
Second, the `ephemeralPubKey` of a first contact has 1121 bytes instead of one 33-byte point,
and that of a memo is empty,
so a tool that assumes `schemeId` 1 lengths has to branch on `schemeId` first.
Third, ERC-5564's three methods cover first contacts only (Section 2.10),
since a memo cannot be checked without channel state.

`schemeId` 5 is compatible with ERC-8441.
A seed gives the same keys and meta-address under both schemes.
A first contact has the same field lengths as a `schemeId` 3 announcement, and the `schemeId` tells them apart.
Neither scheme's scanner matches the other scheme's announcements, since their secrets are domain-separated (Section 1.1).

It keeps ERC-5564's other conventions.
The view tag is the first byte of `metadata`,
which can carry ERC-5564's token metadata after it,
and the methods of Section 2.10 have ERC-5564's signatures.

## Test Cases

Conformance vectors are in the two files below.
Each row states the requirement it pins, its inputs and the expected output,
and, where a mistake is likely, the wrong output it distinguishes.

| file | rows | what it pins |
|---|---|---|
| [`vectors/section-1.json`](../assets/eip-WWWW/vectors/section-1.json) | 6 | Section 1: the offset, its range check, byte order and the view tag |
| [`vectors/section-2.json`](../assets/eip-WWWW/vectors/section-2.json) | 30 | Section 2: keys and seeds, the meta-address and its encapsulation key check, the channel key and its bindings, the first contact and its wire shape, the payment secrets, memos, the scanner's window, replays, and what counts as a skip |

The `V5-` prefix identifies `schemeId` 5 vectors.
Section 1's rows are ERC-8441's, with the same values.
`V1-06` was withdrawn in ERC-8441 when counter-based offset retries were removed; the remaining vector identifiers are retained.

ML-KEM-768 values come from NIST's Automated Cryptographic Validation Protocol (ACVP) test data for FIPS 203,
and each row that uses one names its ACVP test case.
Every other value follows from this document.

Four conventions apply to the vectors:

- **The range check's failure is tested synthetically.**
No findable `ss` produces a `base` that is 0 or at least `n`,
so V1-03 and V1-04 supply `base` directly.
- **Encapsulation is pinned through `Encaps_internal`.**
The vectors fix `m` and use `ML-KEM.Encaps_internal(ek, m)`,
so they pin `ct`, `ss_pq` and the channel key.
A sender using `ML-KEM.Encaps(ek)` opens different,
equally valid channels.
Every scanner-side vector applies to it unchanged.
- **The channel rows start from a channel key.**
V5-20 to V5-24 take V5-06's `k_pairwise` and V5-09's `spending_pk`,
so the payment secrets, memos and the window are pinned independently of any KEM.
- **ML-KEM's edge cases are NIST's own.**
V5-14 takes an ACVP `modified ciphertext` case,
so implicit rejection is checked against NIST's expected value,
and V5-17 and V5-25 a `valid decapsulation` case.
ACVP gives those keys only in expanded form,
so the rows also give `ss_pq` for an implementation that holds keys as `(d, z)` seeds.
V5-19 takes an encapsulation key that NIST's key check rejects.

Two vectors from `section-2.json`:

```
V5-20  k_pairwise = 92568403663a16201625e932c9f00d4b42d6fab4d4a76b81b51d698dbb1e5988
       ss_0       = 9d0584073bf4e12e84e66110a4e98ef895207ea0dc17b5c0f7a1096a67f5fb3e
       ss_1       = 4de33d1df6261ddd2a0cc1f90586af348796352039024ed9e6474ca20d3b5e29
       view_tag   = 06                                                (of ss_1)

V5-23  SCAN_LOOKAHEAD = 20, h = 0; memos sent at counters 21, 20, 1, 1, 21, 41, 2, 22
       skip, match 20, match 1, skip, match 21, match 41, skip, match 22
```

## Security Considerations

### What this scheme protects, and what it does not

`schemeId` 5 protects the announcement layer:
the link between an announcement and its recipient,
against an adversary who reads every announcement and every registered meta-address,
now or after building a cryptographically relevant quantum computer (CRQC).
It does nothing for the rest of the on-chain transaction graph:

- The sender's funding transfer to the stealth address is public,
as in any stealth-address scheme.
- A recipient who spends from or sweeps several stealth addresses into one account links them,
to each other and to that account.
- A stealth EOA that receives only tokens needs ETH for gas.
Whoever funds it is linked to it,
so ERC-5564's discussion of recipients' transaction costs applies unchanged.
- Timing and amounts can correlate payments.

### What the event shape reveals

A first contact and a memo have different `ephemeralPubKey` lengths,
so an observer can count first contacts and memos.
Without the channel key,
an observer can neither tell which channel a memo belongs to nor link it to its first contact,
since the view tag and address of each memo are derived from the channel key.

ERC-5564's `Announcement` event records the calling account as an indexed topic.
A sender that announces every payment from one account links its own announcements to each other,
under every scheme.
A sender that wants its payments to one recipient to be unlinkable to each other SHOULD announce from separate accounts or through a relayer.

### No forward secrecy within a channel

`k_pairwise` is fixed for the life of a channel and derives every payment secret on it.
Anyone who obtains a channel key can link every past and future payment on that channel,
and derive their payment secrets.
Under a per-payment scheme the same loss affects one payment.
A sender that wants to limit it SHOULD open a new channel from time to time,
at the cost of one first contact each.

### KEM anonymity is assumed

The ERC-6538 registry gives an adversary every candidate encapsulation key.
If an ML-KEM-768 ciphertext revealed which `ek` it was intended for,
every first contact, and with it every channel, could be linked to its recipient without decrypting anything.
`schemeId` 5 therefore assumes that ML-KEM-768 is ANO-CCA
(anonymous under chosen-ciphertext attack) as well as IND-CCA,
as ERC-8441 does and for the reasons it gives.
FIPS 203 does not claim anonymity.

The other announcement fields reveal nothing about the recipient,
as long as `k_pairwise` stays secret.
`epk` is independent of the recipient's keys.
The view tags and stealth addresses are functions of payment secrets derived from `k_pairwise`.

### Against a quantum adversary

A quantum adversary can compute `ss_ec` for every first contact and every registered viewing key,
hence the security of `k_pairwise`, and of every payment on the channel, relies entirely on `ss_pq`,
which relies on ML-KEM-768's IND-CCA security and the combiner of Section 1.1.
Conversely, if ML-KEM-768 is broken classically, `ss_ec` keeps `k_pairwise` secret from a classical adversary.
As a channel has no forward secrecy,
breaking one first contact opens every payment on the channel, past and future,
while breaking one ERC-8441 announcement opens one payment.

### Spending once a CRQC exists

Spending is secp256k1, so a CRQC breaks it the way it breaks every EOA.
A spend reveals the stealth address's public key, from which the private key can then be computed.
A CRQC also recovers `spending_sk` from the registered `spending_pk`.
From then on, anyone who holds a channel key can spend every payment on that channel,
and that includes a delegated scanner or anyone who has obtained the tracking key.
What survives a CRQC is the privacy of announcements already published,
for as long as ML-KEM-768 holds.
Funds need a separate migration before that point.

### Delegated scanning

A scanning service given the tracking key opens every first contact,
so it holds every channel key and sees every payment to the recipient, with its timing and count.
That includes every future payment until the recipient registers a new meta-address and every sender opens a new channel to it.
A tracking key cannot be revoked, so ending a delegation means replacing `viewing_ec` and `(d, z)`.
Before a CRQC it cannot spend them.
Section 2.8 explains why disclosing a one-time key to it is forbidden.

### One-time key, payment secret and channel key

A leaked one-time key together with its `ss_i` yields the master spending key,
and so does a leaked one-time key together with its channel key.
A leaked one-time key alone yields nothing.
This follows from ERC-5564's additive derivation.

### Sender state

A sender that reuses a counter repeats a stealth address,
which links two payments on chain and puts both on one key (Section 2.5).
A sender that loses its counter and guesses too high is missed by scanners until they recover,
and one that guesses too low reuses a counter.
The recipient cannot detect either in time to warn the sender.
Hence a sender that may have lost state opens a new channel,
and persists the counter before each payment.
As in ERC-8441, the first contacts of a sender also rely on its random number generator.

### Channel flooding and scanner cost

Anyone holding a recipient's published `ek` can make a first contact that the recipient retains,
at the cost of one first-contact announcement (Cost).
Each retained channel adds a window of up to `2 · SCAN_LOOKAHEAD` counters to derive,
and one lookup to every memo the scanner processes, for as long as it is retained.
A scanner cannot tell an attacker's channels from real ones.
Section 2.7 lets a scanner stop deriving idle channels,
and a scanner SHOULD limit the channels it keeps live with such a policy,
together with the denial-of-service countermeasures discussed in ERC-5564.
To keep a channel live under such a policy, an attacker has to pay for a memo in every period.
A first contact that does not match costs a scanner one ECDH, one decapsulation and no state.
Every malformed field is a skip (Section 2.9),
so malformed input cannot halt a scan.

A match shows that an announcement was addressed to the recipient,
not that anything was paid:
as with `schemeId` 1, a wallet learns what arrived from the stealth address's balances.

### Downgrade

A recipient registered under `schemeId` 1 as well as `schemeId` 5
can be paid under `schemeId` 1 by any sender,
and that payment has no post-quantum announcement privacy.
Section 2.3 is the mitigation:
it forbids senders that implement `schemeId` 5 from using `schemeId` 1 for a recipient registered under `schemeId` 5,
and recommends that recipients who need the protection do not register under `schemeId` 1.
A payment made under `schemeId` 3 keeps its post-quantum announcement privacy.

### View tag

The view tag is one byte of a digest of a payment secret,
separate from the digest that yields the offset.
It tells an observer without the payment secret nothing,
and unlike `schemeId` 1 it does not shorten the offset digest.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
