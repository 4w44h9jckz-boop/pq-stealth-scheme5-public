# Gas benchmarks

From the Rust schemeId 5 fixture (`cargo run --example emit_channel_json -p pqsa-channel`),
using a fresh Prague Anvil, pinned ERC-5564 and ERC-6538 runtime bytecode, creating real
transactions, then reading receipt `gasUsed`.

- `announcement`: standalone ERC-5564 `announce()` calls: the classical reference, the
  fixture channel's first contact and its first memo, each also with ERC-5564's token metadata
- `registration`: first `registerKeys` on the canonical ERC-6538 registry
- `payment`: announce, fund the stealth address, spend with the derived key, for the first
  contact (counter 0) and for the memo (counter 1)

From the repository root:

```bash
python3 harness/bench.py all --check
python3 harness/bench.py all --update
```

`--check` reruns every transaction and requires `measured.json` to match.
`--update` rewrites those files.
Pass `announcement`, `registration`, or `payment` instead of `all` for one benchmark.

`measured.json` stores hardfork, contract identity, fixture identity, calldata length, zero-byte count, and `gasUsed`.
Each row also carries `payload_zero_bytes` and `upper_bound_gas` -- what the same transaction would cost with no zero byte in its payload.
That one is DERIVED from the row beside it by `harness/eip7623.py`, not measured, and it is the only published number that is not a receipt.

## How the committed receipts were produced

The committed `measured.json` files were written with these benchmarks' own case lists, fixture
and EIP-7623 accounting, but each transaction was executed by [revm](https://github.com/bluealloy/revm)
19.7.0 at `SpecId::PRAGUE` instead of Anvil, because Foundry could not be installed where they
were produced. revm first reproduced every receipt the schemeId 3 repository (ERC-8441) measured
on Anvil with the same pinned bytecode: 28 313 and 27 905 for the classical announcement and its
probe, 69 330, 43 991 and 70 550 for the schemeId 3 announcements, 115 310 and 964 737 for the
two registrations, and 21 000 for a transfer.
<!-- gas-external: ERC-8441's Anvil receipts, in that tree's harness/*/measured.json -->

`python3 harness/bench.py all --check` re-runs every transaction on Anvil and fails if any
receipt differs.
