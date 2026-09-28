#!/usr/bin/env python3
"""Read-only Bitcoin sweep audit — single file, standard library only.

Verifies two PINNED public UTXOs against an Esplora-compatible API,
validates a mainnet P2PKH destination, optionally cross-checks against a raw
transaction you supply, and computes fee scenarios from the PINNED values.

Design:
  * Read-only. No seeds, private keys, mnemonics, passphrases, WIFs, PSBTs,
    signatures, or broadcast. Does not scan unknown or generated addresses.
  * Standard library only. No third-party packages, no native extensions.
  * Minimal CPU: a handful of HTTPS GETs and Decimal arithmetic.
  * Runs on Windows cmd / PowerShell, macOS, Linux with CPython 3.9+.

Usage:
    python readonly_sweep_audit.py
    python readonly_sweep_audit.py --json --label "pre-sweep-2026-09-28"
    python readonly_sweep_audit.py --fee-rate 3
    python readonly_sweep_audit.py --local-tx <raw_hex_from_your_node>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from decimal import Decimal, ROUND_DOWN
from urllib.parse import urlparse

API_DEFAULT = "https://blockstream.info/api"
SATS_PER_BTC = 100_000_000

# Pinned fixtures. EXAMPLE values for one specific audit.
# Do not ship user-specific outpoints or destinations in a release build.
SOURCES = {
    "16ZVZJ7c3xyMBHGujrhDWYmAw94Y173FXb": {
        "txid": "26252215001fba609c7dd06442cf8574e73eebf84495fac691b4f727d8564978",
        "vout": 1,
        "sats": 61_840_710,
    },
    "1PnmBU7typd5429CDsuXoJ9BdKjutXNhHj": {
        "txid": "62eeafa27afba19a36095dbab4299159368a8306913768e5ecbf3673d9dc72fd",
        "vout": 0,
        "sats": 16_531_000,
    },
}
DEFAULT_DESTINATION = "1NYbCSn2ksFpULZ2KYbeFUb6vpMJuSpQnP"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PINNED_TOTAL_SATS = sum(v["sats"] for v in SOURCES.values())


# --- helpers ---------------------------------------------------------------

def _b58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    raw = payload + checksum
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + out


def api_get(api: str, path: str):
    parsed = urlparse(api)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("API must be an https URL")
    req = urllib.request.Request(
        api.rstrip("/") + path,
        headers={"User-Agent": "readonly-sweep-audit/2.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def valid_mainnet_p2pkh(address: str) -> bool:
    try:
        n = 0
        for ch in address:
            n = n * 58 + ALPHABET.index(ch)
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        raw = b"\x00" * (len(address) - len(address.lstrip("1"))) + raw
        return (
            len(raw) == 25
            and raw[0] == 0x00
            and hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
            == raw[21:]
        )
    except (ValueError, IndexError):
        return False


def btc(sats: int) -> str:
    return f"{Decimal(sats) / Decimal(SATS_PER_BTC):.8f}"


def _read_varint(buf: bytes, pos: int):
    first = buf[pos]
    if first < 0xFD:
        return first, pos + 1
    if first == 0xFD:
        return int.from_bytes(buf[pos + 1:pos + 3], "little"), pos + 3
    if first == 0xFE:
        return int.from_bytes(buf[pos + 1:pos + 5], "little"), pos + 5
    return int.from_bytes(buf[pos + 1:pos + 9], "little"), pos + 9


def parse_tx_outputs(raw: bytes):
    """Minimal transaction parser. Returns a list of output dicts.

    Decodes only enough to locate P2PKH outputs. Intended for a raw
    transaction you fetched from your own node.
    """
    if len(raw) < 10:
        raise ValueError("transaction too short")
    pos = 4  # version
    if raw[pos:pos + 2] == b"\x00\x01":
        pos += 2
    n_in, pos = _read_varint(raw, pos)
    for _ in range(n_in):
        pos += 36
        slen, pos = _read_varint(raw, pos)
        pos += slen
        pos += 4
    n_out, pos = _read_varint(raw, pos)
    outputs = []
    for _ in range(n_out):
        value = int.from_bytes(raw[pos:pos + 8], "little")
        pos += 8
        slen, pos = _read_varint(raw, pos)
        script = raw[pos:pos + slen]
        pos += slen
        address = None
        if (len(script) == 25 and script[0] == 0x76 and script[1] == 0xA9
                and script[2] == 0x14 and script[23] == 0x88
                and script[24] == 0xAC):
            address = _b58check_encode(b"\x00" + script[3:23])
        outputs.append({
            "value": value,
            "script_pubkey": script.hex(),
            "address": address,
        })
    return outputs


# --- CLI -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="readonly_sweep_audit",
        description=("Read-only audit of two pinned sweep UTXOs. "
                     "Does not sign, broadcast, or handle keys."),
    )
    p.add_argument("--api", default=API_DEFAULT,
                   help="Esplora-compatible API base URL (https only)")
    p.add_argument("--destination", default=DEFAULT_DESTINATION,
                   help="proposed recipient address")
    p.add_argument("--vbytes", type=int, default=341,
                   help="estimated signed transaction virtual size")
    p.add_argument("--fee-rate", type=Decimal, default=None,
                   help="one extra fee scenario in sat/vB")
    p.add_argument("--local-tx", default=None,
                   help="raw funding transaction hex from your own node")
    p.add_argument("--label", default=None,
                   help="free-text label for this audit run")
    p.add_argument("--json", action="store_true",
                   help="emit a JSON report instead of text")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.vbytes <= 0 or args.vbytes > 10_000:
        print("ERROR: --vbytes must be between 1 and 10000", file=sys.stderr)
        return 2
    if args.fee_rate is not None and (
            not args.fee_rate.is_finite() or args.fee_rate < 0):
        print("ERROR: --fee-rate must be a finite non-negative number",
              file=sys.stderr)
        return 2

    dest_ok = valid_mainnet_p2pkh(args.destination)
    if not dest_ok:
        print("ERROR: destination is not a valid mainnet legacy P2PKH address",
              file=sys.stderr)
        return 2

    report = {
        "read_only": True,
        "label": args.label,
        "api": args.api,
        "destination": args.destination,
        "destination_valid_mainnet_p2pkh": dest_ok,
        "vbytes_assumption": args.vbytes,
        "pinned_total_btc": btc(PINNED_TOTAL_SATS),
        "sources": [],
        "fee_scenarios": [],
        "warnings": [],
    }

    # Optional local cross-check first, so we still report it if the API fails.
    if args.local_tx:
        try:
            outputs = parse_tx_outputs(bytes.fromhex(args.local_tx.strip()))
        except Exception as exc:  # noqa: BLE001
            print("ERROR: could not parse --local-tx: %s" % exc, file=sys.stderr)
            return 2
        for address, expected in SOURCES.items():
            matches = [
                {"vout": i, "sats": o["value"]}
                for i, o in enumerate(outputs)
                if o["address"] == address
            ]
            pinned = any(
                m["vout"] == expected["vout"] and m["sats"] == expected["sats"]
                for m in matches
            )
            report["sources"].append({
                "address": address,
                "expected_outpoint": f"{expected['txid']}:{expected['vout']}",
                "expected_sats": expected["sats"],
                "local_tx_matches": matches,
                "local_tx_pinned_output_found": pinned,
                "source": "local-tx",
            })
            if not pinned:
                report["warnings"].append(
                    f"local transaction does not contain {address} output "
                    f"{expected['txid']}:{expected['vout']}"
                )

    ok = True
    live_total_sats = 0

    try:
        for address, expected in SOURCES.items():
            info = api_get(args.api, "/address/" + address)
            utxos = api_get(args.api, "/address/" + address + "/utxo")
            tx = api_get(args.api, "/tx/" + expected["txid"])
            if (not isinstance(info, dict) or not isinstance(utxos, list)
                    or not isinstance(tx, dict)):
                raise ValueError("unexpected API response shape")

            funding_matches = [
                {"vout": i, "sats": v.get("value")}
                for i, v in enumerate(tx.get("vout", []))
                if v.get("scriptpubkey_address") == address
            ]
            pinned_ok = any(
                m["vout"] == expected["vout"] and m["sats"] == expected["sats"]
                for m in funding_matches
            )
            live = [
                u for u in utxos
                if isinstance(u, dict)
                and isinstance(u.get("status"), dict)
                and u["status"].get("confirmed")
                and u.get("txid") == expected["txid"]
                and u.get("vout") == expected["vout"]
                and u.get("value") == expected["sats"]
            ]
            confirmed = [
                u for u in utxos
                if isinstance(u, dict)
                and isinstance(u.get("status"), dict)
                and u["status"].get("confirmed")
                and isinstance(u.get("value"), int)
                and u["value"] >= 0
            ]
            extra = [
                u for u in confirmed
                if not (u["txid"] == expected["txid"]
                        and u["vout"] == expected["vout"])
            ]
            live_sum = sum(u["value"] for u in confirmed)
            live_total_sats += live_sum

            if extra:
                report["warnings"].append(
                    f"{address} has {len(extra)} extra confirmed UTXO(s) "
                    f"beyond the pinned outpoint; they are NOT counted as "
                    f"spendable in this audit"
                )

            report["sources"].append({
                "address": address,
                "expected_outpoint": f"{expected['txid']}:{expected['vout']}",
                "expected_sats": expected["sats"],
                "pinned_output_found_in_funding_tx": pinned_ok,
                "pinned_output_currently_unspent": bool(live),
                "matching_funding_outputs": funding_matches,
                "live_confirmed_utxo_count": len(confirmed),
                "live_confirmed_utxo_sum_btc": btc(live_sum),
                "extra_confirmed_utxo_count": len(extra),
            })
            ok = ok and pinned_ok and bool(live)

    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print("ERROR: API request failed: %s" % exc, file=sys.stderr)
        return 3

    report["live_confirmed_total_btc"] = btc(live_total_sats)

    scenarios = [Decimal("1"), Decimal("2"), Decimal("5"), Decimal("10")]
    if args.fee_rate is not None:
        scenarios.append(args.fee_rate)
    for rate in scenarios:
        fee = int((rate * args.vbytes).to_integral_value(rounding=ROUND_DOWN))
        entry = {
            "sat_per_vbyte": str(rate),
            "vbytes": args.vbytes,
            "fee_sats": fee,
            "fee_btc": btc(fee),
        }
        if fee >= PINNED_TOTAL_SATS:
            entry["error"] = "fee consumes the entire pinned total"
            entry["net_send_btc"] = None
            ok = False
        else:
            entry["net_send_btc"] = btc(PINNED_TOTAL_SATS - fee)
        report["fee_scenarios"].append(entry)

    report["pass"] = ok

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        title = "READ-ONLY SWEEP AUDIT"
        if args.label:
            title += f" [{args.label}]"
        print(title)
        print("API:", args.api)
        print("Destination valid:", report["destination_valid_mainnet_p2pkh"])
        print("Pinned total:", report["pinned_total_btc"], "BTC")
        print("Live confirmed total:", report["live_confirmed_total_btc"], "BTC")
        if report["warnings"]:
            print("Warnings:")
            for w in report["warnings"]:
                print("  -", w)
        for r in report["sources"]:
            print()
            print("Address:", r["address"])
            print("  expected outpoint:", r["expected_outpoint"])
            print("  pinned output in funding tx:",
                  r.get("pinned_output_found_in_funding_tx"))
            print("  pinned output currently unspent:",
                  r.get("pinned_output_currently_unspent"))
            print("  live confirmed UTXOs:", r.get("live_confirmed_utxo_count"))
            print("  extra confirmed UTXOs:", r.get("extra_confirmed_utxo_count"))
            if "local_tx_pinned_output_found" in r:
                print("  local tx cross-check:",
                      r["local_tx_pinned_output_found"])
        print()
        print("Result:", "PASS" if ok else "CHECK FAILED")
        print("Fee scenarios (from pinned total):")
        for s in report["fee_scenarios"]:
            if s.get("error"):
                print(f"  {s['sat_per_vbyte']} sat/vB -> {s['error']}")
            else:
                print(f"  {s['sat_per_vbyte']} sat/vB -> fee {s['fee_btc']} BTC; "
                      f"send {s['net_send_btc']} BTC")
        print()
        print("This tool does not sign or broadcast.")
        print("Re-verify with your own node (gettxout) before signing.")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
