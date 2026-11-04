#!/usr/bin/env python3
"""Live end-to-end native-ETH stealth payment gas benchmark."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.erc5564 import (  # noqa: E402
    ANNOUNCER,
    ANNOUNCER_SHA256,
    install_announcer,
    send_announcement,
)
from harness.evm import (  # noqa: E402
    Anvil,
    DEV_ADDRESS,
    DEV_KEY,
    HARDFORK,
    gas_used,
    quantity,
    require_route,
    rpc,
    run,
    send,
)
from harness.runner import Benchmark, Context, main_one  # noqa: E402
from tools import derive_sizes  # noqa: E402


OUT = Path(__file__).resolve().parent / "measured.json"
FUND_VALUE = 10**18
SPEND_VALUE = 5 * 10**17


def _address(private_key: bytes) -> str:
    return run(
        [
            "cast",
            "wallet",
            "address",
            "--private-key",
            "0x" + private_key.hex(),
        ]
    ).strip()


def _balance(url: str, address: str) -> int:
    return quantity(rpc(url, "eth_getBalance", [address, "latest"]))


def _require_eoa(url: str, address: str, label: str) -> None:
    if rpc(url, "eth_getCode", [address, "latest"]) != "0x":
        raise RuntimeError(f"{label} {address} is not an EOA")


def _announcement_calldata_bytes(shape: str) -> int:
    ephemeral_pub_key_bytes, metadata_bytes = derive_sizes.SHAPES[shape]
    return (
        4
        + 4 * 32
        + 32
        + 32 * ((ephemeral_pub_key_bytes + 31) // 32)
        + 32
        + 32 * ((metadata_bytes + 31) // 32)
    )


def _pay(url: str, scheme_id: int, payment, shape: str) -> dict:
    """Announce one payment, fund its stealth address, and spend from it with its key."""
    stealth_address = "0x" + payment.stealth_address.hex()
    spend_key = "0x" + payment.spend_key.hex()
    if _address(payment.spend_key).lower() != stealth_address.lower():
        raise RuntimeError("fixture spend key does not control the stealth address")
    _require_eoa(url, stealth_address, "stealth address")
    if _balance(url, stealth_address) != 0:
        raise RuntimeError("stealth address did not start empty")

    announce_receipt, calldata = send_announcement(
        url,
        scheme_id,
        stealth_address,
        "0x" + payment.ephemeral_pub_key.hex(),
        "0x" + payment.metadata.hex(),
    )
    calldata_bytes = bytes.fromhex(calldata.removeprefix("0x"))
    if len(calldata_bytes) != _announcement_calldata_bytes(shape):
        raise RuntimeError("announcement transaction has the wrong calldata shape")
    fund_receipt = send(url, DEV_KEY, "--value", str(FUND_VALUE), stealth_address)
    require_route(fund_receipt, DEV_ADDRESS, stealth_address, "fund")
    if _balance(url, stealth_address) != FUND_VALUE:
        raise RuntimeError("fund transaction transferred the wrong value")

    destination_before = _balance(url, DEV_ADDRESS)
    spend_receipt = send(url, spend_key, "--value", str(SPEND_VALUE), DEV_ADDRESS)
    require_route(spend_receipt, stealth_address, DEV_ADDRESS, "spend")
    spend_gas = gas_used(spend_receipt)
    effective_price = quantity(spend_receipt.get("effectiveGasPrice"))
    if _balance(url, DEV_ADDRESS) - destination_before != SPEND_VALUE:
        raise RuntimeError("spend transaction transferred the wrong value")
    expected_remainder = FUND_VALUE - SPEND_VALUE - spend_gas * effective_price
    if _balance(url, stealth_address) != expected_remainder:
        raise RuntimeError("stealth balance does not account for value and fee")
    return {
        "announce": {
            "calldata_bytes": len(calldata_bytes),
            "zero_bytes": calldata_bytes.count(0),
            "gas_used": gas_used(announce_receipt),
        },
        "fund": {"gas_used": gas_used(fund_receipt)},
        "spend": {"gas_used": spend_gas},
    }


def collect(context: Context) -> dict:
    """Pay the fixture channel twice -- the first contact, then a memo -- end to end."""
    fixture = context.fixture
    with Anvil() as node:
        install_announcer(node.url)
        _require_eoa(node.url, DEV_ADDRESS, "spend destination")
        results = [
            {
                "name": "scheme5_first_contact",
                "scheme_id": fixture.scheme_id,
                "kind": "real_sample",
                "counter": fixture.first_contact.counter,
                "transactions": _pay(
                    node.url,
                    fixture.scheme_id,
                    fixture.first_contact,
                    "schemeId 5 first contact",
                ),
            },
            {
                "name": "scheme5_memo",
                "scheme_id": fixture.scheme_id,
                "kind": "real_sample",
                "counter": fixture.memo.counter,
                "transactions": _pay(
                    node.url, fixture.scheme_id, fixture.memo, "schemeId 5 memo"
                ),
            },
        ]
    return {
        "schema_version": 1,
        "benchmark": "payment",
        "environment": {
            "hardfork": HARDFORK,
            "announcer_address": ANNOUNCER,
            "announcer_code_sha256": ANNOUNCER_SHA256,
        },
        "fixture": {
            "name": fixture.name,
            "sha256": fixture.sha256,
        },
        "results": results,
    }


def render(artifact: dict) -> str:
    lines = [
        "schemeId 5 native-ETH payment gas, Rust fixture, Prague",
        "",
        f"{'payment':<24}{'announce':>10}{'fund':>10}{'spend':>10}{'total':>11}",
    ]
    for result in artifact["results"]:
        t = result["transactions"]
        total = sum(observation["gas_used"] for observation in t.values())
        lines.append(
            f"{result['name']:<24}{t['announce']['gas_used']:>10}"
            f"{t['fund']['gas_used']:>10}{t['spend']['gas_used']:>10}{total:>11}"
        )
    return "\n".join(lines)


BENCHMARK = Benchmark("payment", OUT, collect, render)


if __name__ == "__main__":
    raise SystemExit(main_one(BENCHMARK))
