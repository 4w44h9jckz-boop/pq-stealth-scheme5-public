# PQ Stealth Addresses - schemeId 5

Post-quantum stealth-address channels for Ethereum:
one `schemeId` extending [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564)
in which a sender pays the post-quantum key exchange once per recipient.
The first payment, the first contact, carries an ML-KEM-768 encapsulation combined with a
secp256k1 ECDH secret (for implementation risk hedging), and both sides derive a channel key from it.
Each later payment on the channel is a one-byte memo, which costs less gas than a classical
ERC-5564 announcement.
No protocol change.
**Spending stays ordinary secp256k1 ECDSA** -
hence, the announcement layer is post-quantum, the spending is NOT.

schemeId 5 is the channel version of
[ERC-8441 (schemeId 3)](https://github.com/ethereum/ERCs/pull/2059), which encapsulates on
every payment and keeps no state. Both use the same meta-address encoding, key generation,
offset, view tag and combiner, but each scheme has its own keys: a recipient registered under
both uses a different meta-address for each.

| | |
|---|---|
| meta-address, registered once via ERC-6538 | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` = **1 250 B**, as in ERC-8441 |
| first contact, once per sender and recipient | `epk ‖ ct` 1 121 B in `ephemeralPubKey`, `view_tag` 1 B in `metadata` = **1 122 B** |
| memo, each later payment | empty `ephemeralPubKey`, `view_tag` 1 B in `metadata` = **1 B** |
| announcement gas, Prague | **69 240** for the first contact, **26 961** for a memo |
| first-time registration gas | **964 773** |
| a whole payment (announce, fund, spend) | **111 240** on a new channel, **68 961** after |

The all-nonzero classical baseline is 28 313 gas for a 34 B announcement, so a first contact
costs 2.45x a classical announcement and a memo 0.95x. In exchange, both sides keep a channel
key and a counter per counterparty, and a channel has no forward secrecy.

The specification is `spec/ERC-WWWW-schemeid5.md`. It is a draft: it has no ERC number and
no `discussions-to` thread yet, and `schemeId` 5 is not reserved with the ERC-5564 authors.

## What is here

| path | what it is |
|---|---|
| `spec/ERC-WWWW-schemeid5.md` | the specification, in the ERCs repository format; its links resolve once it is at `ERCS/erc-WWWW.md` with the vectors under `assets/eip-WWWW/` |
| `crates/core` | errors, the delegation check, the deterministic seed streams used by the vectors and the harness, and schemeId 3's `StealthScheme` trait |
| `crates/ec` | secp256k1: SEC1 decoding, ECDH, scalar and point addition, the address |
| `crates/kem` | ML-KEM-768, over `ml-kem`, checked against NIST's own ACVP cases |
| `crates/channel` | the scheme itself: keys, first contact, memos, the scanner's channels and window, persistence, and ERC-5564's three methods (`erc5564`) |
| `vectors/` | the fixtures, each row saying what it pins and which wrong output it catches |
| `harness/` | the gas harnesses: real transactions against the pinned contracts, with their receipts |
| `tools/` | fixture generation, size derivation, and offline snapshot/document checks |
| `contracts/` | a readable ERC-5564 announcer source counterpart; the harness pins deployed runtime bytes |

`crates/core`, `crates/ec`, `crates/kem`, `tools/vecprim.py`, the ACVP file, the pinned
contract bytecode and three harness modules are unchanged copies of the schemeId 3 repository's,
so their comments cite ERC-8441's sections. `tools/shared_with_scheme3.json` records the
schemeId 3 commit they match and a sha256 per file, and `tools/check_shared.py` checks them.
`pqsa-channel` does not implement `StealthScheme`, which is stateless, and has its own API
because a channel keeps state.

## Tests

Test with
```bash
cargo test --workspace
python3 tools/run_selftests.py
python3 tools/gen_vectors.py --check
```

`cargo test` runs the unit tests and `crates/channel/src/spec_vectors.rs`, which runs all 37
committed vector rows through the implementation.
`run_selftests.py` runs the three `tools/test-*.py` scripts (sizes, vector generator, snapshot and docs).
`gen_vectors.py --check` regenerates `vectors/` and compares it to what is committed.
`check_measured.py` and `check_shared.py` are included in `run_selftests.py`.
`python3 tools/check_shared.py --against ../pq-stealth-scheme3-public` compares the shared files
with a schemeId 3 checkout directly.

Gas, against a local Anvil node:

```bash
python3 harness/bench.py all --check
```

The committed receipts were computed with revm instead of Anvil (see `harness/README.md`).
The command above measures them again on Anvil.

The fixtures are generated from `tools/vecprim.py` and `tools/gen_vectors.py`,
which are **independent** from the reference implementation that they test:
the payment secrets, the scanner's window and the replay rules are implemented once in Python
from the specification and once in Rust.
For ML-KEM: the ciphertexts are of **NIST's own ACVP file**, vendored at `vectors/tier1/`.

## Compatibility with schemeId 3

- Each scheme has its own keys. Key generation and the meta-address encoding are ERC-8441's,
  but the spec (Sections 2.1 and 2.3) forbids registering schemeId 5 keys under any other
  `schemeId`, and a sender MUST NOT pay under schemeId 5 when another registry entry of the
  recipient contains one of them. `MetaAddress::shares_keys_with` is that check, and V5-26
  pins it. A wallet deriving keys from one master should use a different seed per scheme, for
  example `pqsa_core::keygen_seed(master, 5, NAME, j, 128)`.
- A first contact has the same field lengths as a schemeId 3 announcement; the `schemeId` tells them apart.
- Neither scheme's scanner matches the other's announcements: the combiner's domain
  separators differ (`pq-stealth/hybrid-payment/v1` and `pq-stealth/pairwise/v1`). V5-06c
  checks this for a schemeId 3 announcement.
- A sender that also implements ERC-8441 follows its Section 2.3, so it pays a recipient
  registered under both schemeIds under schemeId 3.
- The vectors in `section-1.json` have the same values as ERC-8441's.
- `crates/core`, `crates/ec` and `crates/kem` are byte-identical to the schemeId 3 repository's,
  so a wallet that uses both schemes can build one copy of them, for example with a Cargo
  `[patch]` section pointing both at the same source.

## Differences from the reference channel draft

The pairwise channel was first drafted, as schemeIds 4 and 5, in the PQ_SA_Reference
repository (`ERC-WWWW-channel.md`). This repository specifies schemeId 5 only, and follows
ERC-8441's conventions instead of that draft's:

| | reference draft | here |
|---|---|---|
| view tag | 8 bytes, the only check on a memo | 1 byte at `metadata[0]`, as in ERC-5564; the announced `stealthAddress` decides every match |
| first contact | `epk` in `ephemeralPubKey`, `view_tag ‖ ct` in `metadata`, 1 129 B | `epk ‖ ct` in `ephemeralPubKey`, `view_tag` in `metadata`, 1 122 B, as in ERC-8441, so ERC-5564's token metadata keeps its place |
| memo | 8 B | 1 B, the view tag |
| sender randomness | derived from a persisted index | drawn from a CSPRNG, as in ERC-8441 |
| offset | counter-based retry | range check that fails, as in ERC-8441; a sender skips a counter whose offset fails |
| scanner window | above the highest matched counter | also `SCAN_LOOKAHEAD` below it, to find memos included out of order; matched counters are remembered, so replays are not reported twice |
| `SCAN_LOOKAHEAD` | left open | 20, as BIP 44 fixes its gap limit |
| watch delegation | per-channel `(k_pairwise, next)`, matched on the 8-byte tag | not specified: with a 1-byte tag a watcher would need the addresses |
| idle channels | three named constants and a margin | a scanner MAY retire an idle channel, MUST NOT show it as live, and SHOULD be able to resume it; no constants |
| ERC-5564 methods | not defined | defined for first contacts; memos need channel state |

## Secret ownership

Owned seeds, shared secrets, channel keys and offsets use `zeroize::Zeroizing`; spending keys use
`secrecy::SecretBox<[u8; 32]>`. Borrow signer input with `pqsa_channel::spend_key_bytes(&key)`.
Persisted channel records (`SenderChannel::to_bytes`, `ScannerChannel::to_bytes`) are secret and
are returned as `Zeroizing<Vec<u8>>`. The aggregate secret types redact their `Debug` output.

## Sender and scanner channels

`SenderChannel` and `ScannerChannel` are separate types with no conversion between them, and
each persisted record starts with a role byte that the other type refuses. So a wallet that
both sends and receives cannot report its own memos as incoming payments by mistake.

## Randomness and key seeds

`open_random` is the sender: it draws `esk` and ML-KEM's `m` from the operating system's CSPRNG,
as the spec's Section 2.4 requires. The seeded `open` takes that randomness as input so the
vectors and the gas harness are reproducible; it is not a sender for real payments. The harness
feeds it seeds from SHAKE256 over a fixed secret and a counter. Its keygen seed is derived with
`keygen_seed` from a fixed master key for schemeId 5, so its keys are not the schemeId 3
fixture's.

`keygen_seed` in `crates/core` derives a keygen seed from a 32-byte master key with HKDF-SHA256.
It is one way to meet the spec's Section 2.1, not part of the standard.

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
