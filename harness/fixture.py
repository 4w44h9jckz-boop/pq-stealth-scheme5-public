"""Real deterministic schemeId 5 fixture produced by the Rust implementation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from harness.evm import run
from tools import derive_sizes


ROOT = Path(__file__).resolve().parent.parent
COMMAND = [
    "cargo",
    "run",
    "-q",
    "--example",
    "emit_channel_json",
    "-p",
    "pqsa-channel",
    "--locked",
]
PAYMENT_FIELDS = {
    "counter",
    "stealth_address",
    "spend_key",
    "ephemeral_pub_key",
    "metadata",
}


def _hex(value: object, field: str, size: int) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"fixture field {field} is not 0x-prefixed hex")
    try:
        decoded = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise RuntimeError(f"fixture field {field} is not valid hex") from exc
    if len(decoded) != size:
        raise RuntimeError(
            f"fixture field {field} is {len(decoded)} bytes, expected {size}"
        )
    return decoded


@dataclass(frozen=True)
class Payment:
    """One announced payment on the fixture channel, with the key that spends it."""

    counter: int
    stealth_address: bytes
    spend_key: bytes
    ephemeral_pub_key: bytes
    metadata: bytes


@dataclass(frozen=True)
class Fixture:
    """One identified schemeId 5 fixture: a meta-address and a channel's first two payments."""

    name: str
    sha256: str
    scheme_id: int
    meta_address: bytes
    first_contact: Payment
    memo: Payment


def _payment(body: object, label: str, shape: tuple[int, int], counter: int) -> Payment:
    if not isinstance(body, dict) or set(body) != PAYMENT_FIELDS:
        raise RuntimeError(f"fixture {label} does not match the payment schema")
    if body["counter"] != counter:
        raise RuntimeError(f"fixture {label} is at counter {body['counter']}, not {counter}")
    return Payment(
        counter=counter,
        stealth_address=_hex(body["stealth_address"], f"{label}.stealth_address", 20),
        spend_key=_hex(body["spend_key"], f"{label}.spend_key", 32),
        ephemeral_pub_key=_hex(
            body["ephemeral_pub_key"], f"{label}.ephemeral_pub_key", shape[0]
        ),
        metadata=_hex(body["metadata"], f"{label}.metadata", shape[1]),
    )


def generate() -> Fixture:
    """Run and strictly decode the deterministic Rust fixture generator."""
    try:
        body = json.loads(run(COMMAND, cwd=ROOT))
    except json.JSONDecodeError as exc:
        raise RuntimeError("fixture generator did not emit valid JSON") from exc
    fields = {"name", "scheme_id", "meta_address", "first_contact", "memo"}
    if not isinstance(body, dict) or set(body) != fields:
        raise RuntimeError("fixture output does not match the fixture schema")
    if body["name"] != "scheme5-demo-v1" or body["scheme_id"] != 5:
        raise RuntimeError("fixture output has an unknown identity")

    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return Fixture(
        name=body["name"],
        sha256=hashlib.sha256(canonical).hexdigest(),
        scheme_id=body["scheme_id"],
        meta_address=_hex(
            body["meta_address"], "meta_address", derive_sizes.META["schemeId 5"][0]
        ),
        first_contact=_payment(
            body["first_contact"],
            "first_contact",
            derive_sizes.SHAPES["schemeId 5 first contact"],
            0,
        ),
        memo=_payment(body["memo"], "memo", derive_sizes.SHAPES["schemeId 5 memo"], 1),
    )
