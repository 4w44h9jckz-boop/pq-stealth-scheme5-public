# Conformance vector plan — schemeId 5, and what it shares

## 1. Each test vector is explainable

Each file is `{"section": ..., "vectors": {id: row}}`,
and each row states the claim,
its inputs, the expected output and the wrong outputs it distinguishes, e.g. V1-03:

```json
"V1-03": {
  "claim":  "the range check MUST reject base = 0",
  "given":  { "base": "0000…0000" },
  "expect": { "outcome": "fail" },
  "wrong":  { "offset": "0000…0000",
              "note": "no range check: offset 0 makes the stealth address the address of
                       spending_pk itself, which links the payment to the registered key" }
}
```

`wrong` is left out where no likely mistake needs naming (V1-01).
A row whose constant is still a proposal also carries `"provisional":
true` and a `provisional_because`.

### Two tiers of test vectors

| tier | covers | oracle | who generates it |
|---|---|---|---|
| 1 | ML-KEM-768 itself | **FIPS 203 / NIST ACVP** | nobody — vendored at a pinned commit |
| 2 | **everything below** | the specification text | a standalone generator, no project code |

### One recipient, three KEM keys

NIST's ACVP keygen, encapsulation and decapsulation cases use different keys, and the
generator runs no KEM, so the rows use three keys:

- **V5-09's recipient** holds the `(d, z)` of an ACVP keygen case, so its meta-address carries
  NIST's `ek`. It is the same recipient as ERC-8441's vectors (V3-09).
- **V5-06's channel key** comes from an ACVP encapsulation case (`ek`, `m`, `ct`, `ss_pq`) and
  a fixed `esk`. The channel rows V5-20 to V5-24 start from that key and V5-09's `spending_pk`.
- **V5-14, V5-17 and V5-25** take an ACVP decapsulation case, whose `dk` exists only in
  expanded form, as the recipient's KEM key, and give `ss_pq` for an implementation that holds
  keys as `(d, z)` seeds.

---

## 2. Section1 — common definitions

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V1-01 | `H(ss) = SHA256(DS_offset ‖ ss)`, range-checked | a fixed `ss` | `base`, and `offset = base` | — |
| V1-02 | **every digest is big-endian** | an `ss` whose digest starts `0x01` and ends `0x80` | the integer, MSB first | little-endian read gives a different scalar, therefore a different address, therefore **funds the recipient cannot spend**. Silent and total |
| V1-03 | the range check MUST reject `base = 0` | `base = 0x00…00` | failure | `offset = 0` — no range check, and the stealth address is then the address of `spending_pk` itself |
| V1-04 | the range check MUST reject `base = n` | `base = n_secp256k1` | failure | reduced mod n to 0, which some libraries do silently |
| V1-05 | `base = n − 1` is **valid** | `base = n − 1` | `offset = n − 1` | rejected — an off-by-one in the bound loses a legitimate payment |
| V1-06 | ~~the counter byte is a single byte appended~~ WITHDRAWN: Section 1 does not retry with a counter, as in ERC-8441 | — | — | — |
| V1-07 | `view_tag = SHA256(DS_viewtag ‖ ss)[0]` | a fixed `ss` | one byte | an eight-byte tag, `[0..8]`, which matches nothing a conforming sender emits; taking `[31]` instead of `[0]`; or the leading byte of `H(ss)` instead of a separate digest |

Section1 is ERC-8441's, row for row: every value in `section-1.json` is the same, and only
V1-07's note differs, because it cites this document's sections.

## 3. Section2 — schemeId 5

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V5-01 | keygen seed is 128 B | 128 B; then 96 B and 127 B | outputs; then errors | accepting a 96-byte seed, a well-formed seed for a scheme with no EC half |
| V5-02 | keygen MUST reject a seed whose `spending_seed` equals any 32-byte component of the tracking key: `viewing_ec_seed`, `d` or `z` | `spending_seed` copied into each component in turn | error, all three times | comparing against `viewing_ec_seed` alone, which misses the same 32 bytes copied into the KEM seed a scanning service receives |
| V5-02a | a keygen with no equal component is accepted | a clean delegated object | outputs, no error | rejecting valid keygens: the positive control for V5-02 |
| V5-03 | meta is 1 250 B and both points are validated | a `0x05`-tagged `viewing_pk_ec` | error at decode | validating only `spending_pk` |
| V5-04 | `ss_ec` is the x-coordinate alone | `esk`, `viewing_pk_ec` | 32 bytes | the 65-byte point, or the 33-byte compressed form → a different channel key, silently |
| V5-05 | the channel-key domain separator `"pq-stealth/pairwise/v1"` is the first input, neither appended nor length-prefixed | the IKM | `k_pairwise` | appending it, or length-prefixing it |
| V5-06 | IKM is exactly `ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek`, in that order | the six parts | `k_pairwise` | any other order, and any omission; the three-field form, and the KEM-only channel key `SHA3-256("pq-stealth/pairwise-pq/v1" ‖ ss_pq)` |
| V5-06a | `ct` is bound in | two first contacts with the same `epk` and `ss_ec` but different `ct` | different keys | the same key, which loses the combiner's IND-CCA argument |
| V5-06b | `viewing_pk_ec` is bound in | one `ss_ec` against two registered viewing keys | different keys | the same key |
| V5-06c | the channel key is not ERC-8441's payment secret, and an ERC-8441 announcement is a skip under schemeId 5 | V5-06's parts, and the schemeId 3 announcement ERC-8441's sender makes from them | different values; skip, nothing retained | reusing `"pq-stealth/hybrid-payment/v1"`, which makes a schemeId 3 announcement open a channel |
| V5-07 | `epk` MUST be bound in | the parity byte flipped `0x02`↔`0x03` | a different key | the same key: the flipped point has the same x-coordinate |
| V5-08 | first-contact wire shape | `epk`, `ct`, `k_pairwise` | `epk ‖ ct` 1 121 B in `ephemeralPubKey`, `view_tag(ss_0)` 1 B in `metadata`, `stealthAddress` of `ss_0` | `ct ‖ epk`, the same length as the right answer; or `ct` in `metadata`, which a conforming scanner skips on the `ephemeralPubKey` length |
| V5-08a | the view tag is `metadata[0]`, and later bytes are ignored | `metadata` = the tag alone, then the tag and ERC-5564's 56-byte native-token block | both parse, to the same tag | requiring `metadata` to be exactly one byte, which skips every sender following ERC-5564's token-metadata recommendation |
| V5-09 | keygen MUST be deterministic in the seed | a 128-byte seed whose `kem_seed` is ACVP keygen `(d, z)` | the 1 250-byte meta-address, the 96-byte tracking key, the 32-byte master | calling the KEM's randomness-taking keygen and ignoring `kem_seed`: undetectable until the owner restores from seed and can open no channel |
| V5-10 | `spending_seed` and `viewing_ec_seed` MUST each be a valid secp256k1 scalar | `0`, `n`, `n − 1`, and `viewing_ec_seed = 0` | error, error, accepted, error | reducing mod `n`: `spending_seed = n` becomes `0`, and every payment is spendable by anyone |
| V5-11 | decoding MUST reject a meta-address length other than 1 250 | 1 249, 1 250, 1 251 | error, accepted, error | slicing with no length check |
| V5-12 | 33 bytes of the right length can still be a non-point | `0x02 ‖ x` for `x = 5`; then a valid key | error at decode, then accepted | checking the length and tag byte only |
| V5-13 | `address = keccak256(uncompressed(pk)[1..])[12..32]` | V5-16's `stealth_pk`, both encodings | the 20-byte address and its EIP-55 form | keccak of the compressed form; with the `0x04` prefix; `[0..20]` |
| V5-14 | a view-tag mismatch at counter 0 is a skip that retains nothing: and decapsulation does not fail | ACVP decapsulation tcId 88, `modified ciphertext`, as the recipient's KEM key; a first contact with the derived address and a wrong tag | 32 bytes and no error; skip, nothing retained; match and retain after correcting only the tag | retaining a channel because decapsulation succeeded, which keeps a channel for every first contact anyone publishes |
| V5-15 | the `ephemeralPubKey` length selects first contact (1 121) or memo (0), and any other shape is a skip at the entry point | `ephemeralPubKey` of 0, 1, 33, 1 120, 1 121, 1 122 B; `metadata` of 0, 1, 57 B | skip if `metadata` is empty; first contact at 1 121, memo at 0, skip otherwise | raising on a stranger's bytes; or treating a memo's empty field as malformed, which loses every payment after the first |
| V5-16 | the stealth key pair of the payment at counter 0 | V5-09's spending key and `ss_0`; then `spending_sk = n − 1` | `H(ss_0)`, `stealth_pk`, `stealth_sk`, the address; the sum past `n` reduced mod `n` | a multiplicative tweak; hashing `k_pairwise` instead of `ss_0`, which gives one address for the whole channel; reducing mod 2^256 |
| V5-17 | the announced `stealthAddress` decides a first contact: a view-tag match with a different address is a skip and retains nothing | ACVP decapsulation tcId 86, `valid decapsulation`, as the recipient's KEM key; the honest address, then the one a sender that hashed the `0x04` prefix announces | match and retain; skip and retain nothing | deciding on the one-byte tag, which lets 1 in 256 foreign first contacts through |
| V5-18 | a 1 121-byte `ephemeralPubKey` whose `epk` is not a valid point is a skip | `epk` tagged `0x05`, `0x04`, `0x00`; `x = 5`; `x = p + 1` | skip for each; the honest `epk` is processed | raising from the curve library; canonicalising `0x05`, or reducing `x` mod `p` |
| V5-19 | an `ek` that fails FIPS 203's encapsulation key check is an error, and no first contact is made | ACVP encapsulationKeyCheck tcId 137 (`testPassed: false`), then tcId 136 | error; then an encapsulation | encapsulating anyway, to a key other than the registered one |
| V5-20 | `ss_i = SHA256("pq-stealth/pairwise-payment/v1" ‖ k_pairwise ‖ u128be(i))` | V5-06's key, counters 0, 1, 2 and 2^64 | four payment secrets and view tags | an 8-byte counter, a little-endian one, or the separator appended: each a different secret, and the counter is never published to correct it |
| V5-21 | the first contact is the payment at counter 0 | V5-06's key and V5-09's `spending_pk` | `ss_0`, its view tag and its address | deriving the first payment from `k_pairwise` itself, or starting at counter 1; and admitting the channel without deriving the payment, which loses the first payment on every channel |
| V5-22 | a memo is `stealthAddress`, an empty `ephemeralPubKey` and the view tag, starting at counter 1 | V5-06's key, counters 1 to 3 | three memos of 1-byte payload | a memo at counter 0, which repeats the first contact's address; or the counter on the wire |
| V5-23 | the window: a memo is tried at every unmatched counter `c ≥ 1` with `h − SCAN_LOOKAHEAD < c ≤ h + SCAN_LOOKAHEAD` | V5-21's channel at `h = 0`, `SCAN_LOOKAHEAD = 20`, memos sent at counters 21, 20, 1, 1, 21, 41, 2, 22 | skip, match 20, match 1, skip, match 21, match 41, skip, match 22 | trying only counters above `h`, which loses out-of-order memos; an unbounded window below `h`; or matching a replayed memo twice |
| V5-24 | the announced `stealthAddress` decides a memo | V5-21's channel; the memo at counter 1, then with another address | match; skip, and `h` stays 0 | matching memos on the one-byte tag, which foreign memos carry 1 time in 256 per counter tried |
| V5-25 | a replayed first contact retains one channel and reports no second payment | V5-17's first contact, its memo at counter 1, then the first contact again | match 0, match 1, skip; one channel, `h = 1` | retaining it again, which grows the list or rewinds `h`; or reporting counter 0 twice |

## 4. Deliverables, in order

1. `tools/gen_vectors.py`: standalone, Python standard library only, with its arithmetic in
   `tools/vecprim.py`. It imports nothing from the implementation in `crates/`, and emits one
   JSON file per section plus a manifest with a sha256 per file.
2. `vectors/*.json`: the sets above, committed.
3. `crates/channel/src/spec_vectors.rs`: runs every row through the reference implementation.

## 5. What no fixture can check

| | why a fixture cannot reach it |
|---|---|
| role separation (Section 2.7) | a requirement on the shape of state, not an input/output pair. The reference has separate sender and scanner types and role-tagged persistence, unit-tested |
| a counter whose offset fails | no findable counter makes `H(ss_i)` fail, so the sender's skip (Section 2.5) has no input to pin |
| sender randomness and counter non-reuse | properties of a sequence of calls |
| the master-recovery hazard | an assertion about what an implementation must not disclose |
| recovery with a wider window | a choice of the recovering scanner; the reference tests it as a unit |
