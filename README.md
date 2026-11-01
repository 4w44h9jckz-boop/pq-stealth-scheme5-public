# PQ Stealth Addresses — schemeId 5

Post-quantum stealth-address **channels** for Ethereum:
one `schemeId` extending [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564)
in which a sender pays the post-quantum key exchange **once per recipient**.
The first payment, the first contact, carries an ML-KEM-768 encapsulation combined with a
secp256k1 ECDH secret (for implementation risk hedging) and derives a channel key both sides keep.
Every later payment on the channel is a **one-byte memo**, and costs less gas than a
classical ERC-5564 announcement.
No protocol change.
**Spending stays ordinary secp256k1 ECDSA** -
hence, the announcement layer is post-quantum, the spending is NOT.

This is the channel counterpart of
[ERC-8441 (schemeId 3)](https://github.com/ethereum/ERCs/pull/2059), which pays the
encapsulation on every payment and keeps no state. The two share their meta-address, key
generation, offset, view tag and combiner, so one registered meta-address serves both.

| | |
|---|---|
| meta-address, registered once via ERC-6538 | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` = **1 250 B**, as ERC-8441 |
| first contact, once per sender and recipient | `epk ‖ ct` 1 121 B in `ephemeralPubKey`, `view_tag` 1 B in `metadata` = **1 122 B** |
| memo, every later payment | empty `ephemeralPubKey`, `view_tag` 1 B in `metadata` = **1 B** |
| announcement gas, Prague | **69 090** for the first contact, **26 961** for a memo |
| first-time registration gas | **964 737** |
| a whole payment (announce, fund, spend) | **111 090** on a new channel, **68 961** after |

The all-nonzero classical baseline is 28 313 gas for a 34 B announcement, so a first contact is
**2.44x** a classical announcement and a memo **0.95x**. What a channel costs instead is state:
both sides keep a channel key and a counter per counterparty, and a channel has no forward
secrecy.

The specification is `spec/ERC-WWWW-schemeid5.md`, in draft: no ERC number, no
`discussions-to` thread, and `schemeId` 5 is not reserved with the ERC-5564 authors.

## What is here

| path | what it is |
|---|---|
| `spec/ERC-WWWW-schemeid5.md` | the specification, in the ERCs repository's format; its links resolve once it sits at `ERCS/erc-WWWW.md` with the vectors under `assets/eip-WWWW/` |
| `crates/core` | errors, the delegation guard, and the deterministic seed streams the vectors and harness use |
| `crates/ec` | secp256k1: SEC1 decoding, ECDH, scalar and point addition, the address |
| `crates/kem` | ML-KEM-768, over `ml-kem`, checked against NIST's own ACVP cases |
| `crates/channel` | the scheme itself: keys, first contact, memos, the scanner's channel book and window, role-tagged persistence, and ERC-5564's three methods for it (`erc5564`) |
| `vectors/` | the fixtures saying what each row pins and which wrong output it distinguishes |
| `harness/` | the gas harnesses: real transactions against the pinned contracts, with their receipts |
| `tools/` | fixture generation, size derivation, and offline snapshot/document checks |
| `contracts/` | a readable ERC-5564 announcer source counterpart; the harness pins deployed runtime bytes |

`crates/core`, `crates/ec`, `crates/kem`, `tools/vecprim.py` and the ACVP file are the schemeId 3
tree's, with schemeId 3's stateless `StealthScheme` trait removed from `core`: a channel is
stateful, so `pqsa-channel` carries its own API.

## Tests

Test with
```bash
cargo test --workspace
python3 tools/run_selftests.py
python3 tools/gen_vectors.py --check
```

`cargo test` runs the crates' unit tests and `crates/channel/src/spec_vectors.rs`, which drives
all 36 committed vector rows through the implementation.
`run_selftests.py` runs the three `tools/test-*.py` scripts (sizes, vector generator, snapshot and docs).
`gen_vectors.py --check` regenerates `vectors/` and compares it to what is committed.
`check_measured.py` is included in `run_selftests.py`.

Gas, against a local Anvil node:

```bash
python3 harness/bench.py all --check
```

The committed receipts were computed with revm at Prague rather than Anvil, after revm
reproduced every ERC-8441 Anvil receipt; `harness/README.md` says how, and the command above
re-measures them on Anvil.

The fixtures are generated from `tools/vecprim.py` and `tools/gen_vectors.py`,
which are **independent** from the reference implementation that they test:
the scanner's window, the payment secrets and the replay rules are written twice, once in
Python from the specification and once in Rust.
For ML-KEM: the ciphertexts are of **NIST's own ACVP file**, vendored at `vectors/tier1/`.

## How this differs from the reference channel draft

The pairwise channel was first drafted, as schemeIds 4 and 5, in the PQ_SA_Reference
repository's `ERC-WWWW-channel.md`. This tree specifies schemeId 5 alone, and on ERC-8441's
conventions rather than that draft's:

| | reference draft | here |
|---|---|---|
| view tag | 8 bytes, the only check on a memo | 1 byte at `metadata[0]`, as ERC-5564; the announced `stealthAddress` decides every match |
| first contact | `epk` in `ephemeralPubKey`, `view_tag ‖ ct` in `metadata`, 1 129 B | `epk ‖ ct` in `ephemeralPubKey`, `view_tag` in `metadata`, 1 122 B: ERC-8441's shape, leaving ERC-5564's token metadata in place |
| memo | 8 B | 1 B, the view tag |
| sender randomness | derived from a persisted index | drawn from a CSPRNG, as ERC-8441 |
| offset | counter-based retry | range check that fails, as ERC-8441; a sender skips a failing counter |
| scanner window | above the highest matched counter | also `SCAN_LOOKAHEAD` below it, so memos included out of order are found, and matched counters are remembered so replays are not |
| `SCAN_LOOKAHEAD` | left to the ecosystem | fixed at 20, as BIP44 fixes its gap limit |
| watch delegation | per-channel `(k_pairwise, next)` matched on the 8-byte tag | not specified: with a one-byte tag a watcher needs the addresses, which the tag alone no longer identifies |
| idle windows | three named constants and a margin | a scanner MAY retire an idle channel, MUST NOT show it as live, SHOULD be able to resume it; no constants |
| ERC-5564 methods | not defined | defined for first contacts; memos need channel state |

## Secret ownership

Owned seeds, shared secrets, channel keys and offsets use `zeroize::Zeroizing`; spending keys use
`secrecy::SecretBox<[u8; 32]>`. Borrow signer input with `pqsa_channel::spend_key_bytes(&key)`.
Persisted channel records (`SenderChannel::to_bytes`, `ScannerChannel::to_bytes`) are secret and
come back as `Zeroizing<Vec<u8>>`. The aggregate secret types redact their `Debug` output.

## Roles

`SenderChannel` and `ScannerChannel` are different types with no conversion between them, and
each persisted record starts with a role byte the other type's parser refuses. A wallet that
both sends and receives therefore cannot report its own outgoing memos as incoming payments by
accident. A holder of the secrets can still relabel them deliberately; the specification's
MUST covers that.

## Randomness and key seeds

`open_random` is the sender: it draws `esk` and ML-KEM's `m` from the operating system's CSPRNG,
as the spec's Section 2.4 requires. The seeded `open` takes that randomness as input so the
vectors and the gas harness are reproducible; it is not a sender for real payments. The harness
feeds it seeds from SHAKE256 over a fixed secret and a counter, and takes its keys from the same
fixed 128-byte keygen seed as the schemeId 3 tree, so both trees' fixtures share one meta-address.

`keygen_seed` in `crates/core` derives a keygen seed from a 32-byte master key with HKDF-SHA256.
It is one way to meet the spec's Section 2.1, not part of the standard.

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
