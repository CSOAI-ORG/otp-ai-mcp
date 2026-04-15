#!/usr/bin/env python3
"""Generate and verify TOTP/HOTP one-time passwords with RFC 4226/6238 compliance. — MEOK AI Labs."""

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import json, hashlib, hmac, struct, time, base64, secrets
from datetime import datetime, timezone
from collections import defaultdict
from urllib.parse import quote
from mcp.server.fastmcp import FastMCP

FREE_DAILY_LIMIT = 30
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now - t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT:
        return json.dumps({"error": f"Limit {FREE_DAILY_LIMIT}/day. Upgrade: meok.ai"})
    _usage[c].append(now)
    return None

mcp = FastMCP("otp-ai", instructions="Generate and verify TOTP/HOTP one-time passwords with RFC 4226/6238 compliance. By MEOK AI Labs.")

VALID_ALGORITHMS = ["sha1", "sha256", "sha512"]
VALID_DIGITS = [6, 7, 8]


def _base32_encode(data: bytes) -> str:
    """Encode bytes to base32 (RFC 4648) without padding."""
    return base64.b32encode(data).decode('ascii').rstrip('=')


def _base32_decode(encoded: str) -> bytes:
    """Decode base32 string, handling missing padding."""
    encoded = encoded.upper().strip()
    padding = (8 - len(encoded) % 8) % 8
    encoded += '=' * padding
    return base64.b32decode(encoded)


def _hotp(secret_bytes: bytes, counter: int, digits: int = 6, algorithm: str = "sha1") -> str:
    """Generate HOTP code per RFC 4226."""
    hash_func = getattr(hashlib, algorithm)
    msg = struct.pack('>Q', counter)
    h = hmac.new(secret_bytes, msg, hash_func).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def _totp(secret_bytes: bytes, period: int = 30, digits: int = 6, algorithm: str = "sha1", timestamp: float = None) -> str:
    """Generate TOTP code per RFC 6238."""
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp) // period
    return _hotp(secret_bytes, counter, digits, algorithm)


@mcp.tool()
def generate_otp(secret: str, otp_type: str = "totp", digits: int = 6, period: int = 30, algorithm: str = "sha1", counter: int = 0, api_key: str = "") -> str:
    """Generate a one-time password from a base32 secret. Supports TOTP (time-based) and HOTP (counter-based)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if err := _rl():
        return err

    otp_type = otp_type.lower().strip()
    algorithm = algorithm.lower().strip()

    if otp_type not in ("totp", "hotp"):
        return json.dumps({"error": "otp_type must be 'totp' or 'hotp'"})
    if digits not in VALID_DIGITS:
        return json.dumps({"error": f"digits must be one of: {VALID_DIGITS}"})
    if algorithm not in VALID_ALGORITHMS:
        return json.dumps({"error": f"algorithm must be one of: {VALID_ALGORITHMS}"})
    if period < 15 or period > 120:
        return json.dumps({"error": "period must be between 15 and 120 seconds"})

    try:
        secret_bytes = _base32_decode(secret)
    except Exception:
        return json.dumps({"error": "Invalid base32 secret. Use generate_secret to create one."})

    now = time.time()

    if otp_type == "totp":
        code = _totp(secret_bytes, period, digits, algorithm, now)
        current_counter = int(now) // period
        seconds_remaining = period - (int(now) % period)
        return json.dumps({
            "otp": code,
            "type": "totp",
            "digits": digits,
            "period": period,
            "algorithm": algorithm,
            "seconds_remaining": seconds_remaining,
            "counter": current_counter,
            "valid_until": datetime.fromtimestamp(((current_counter + 1) * period), tz=timezone.utc).isoformat(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    else:
        code = _hotp(secret_bytes, counter, digits, algorithm)
        return json.dumps({
            "otp": code,
            "type": "hotp",
            "digits": digits,
            "algorithm": algorithm,
            "counter": counter,
            "next_counter": counter + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


@mcp.tool()
def verify_otp(secret: str, code: str, otp_type: str = "totp", digits: int = 6, period: int = 30, algorithm: str = "sha1", counter: int = 0, window: int = 1, api_key: str = "") -> str:
    """Verify a one-time password against a secret. Window parameter allows for clock drift (TOTP) or counter desync (HOTP)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if err := _rl():
        return err

    otp_type = otp_type.lower().strip()
    algorithm = algorithm.lower().strip()
    window = max(0, min(window, 5))

    try:
        secret_bytes = _base32_decode(secret)
    except Exception:
        return json.dumps({"error": "Invalid base32 secret"})

    code = code.strip()
    if not code.isdigit() or len(code) != digits:
        return json.dumps({"valid": False, "reason": f"Code must be {digits} digits"})

    now = time.time()

    if otp_type == "totp":
        current_counter = int(now) // period
        for offset in range(-window, window + 1):
            test_counter = current_counter + offset
            expected = _hotp(secret_bytes, test_counter, digits, algorithm)
            if hmac.compare_digest(code, expected):
                return json.dumps({
                    "valid": True,
                    "type": "totp",
                    "drift": offset,
                    "drift_seconds": offset * period,
                    "counter_matched": test_counter,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        return json.dumps({
            "valid": False,
            "type": "totp",
            "reason": "Code does not match within the allowed window",
            "window": window,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    else:
        for offset in range(window + 1):
            test_counter = counter + offset
            expected = _hotp(secret_bytes, test_counter, digits, algorithm)
            if hmac.compare_digest(code, expected):
                return json.dumps({
                    "valid": True,
                    "type": "hotp",
                    "counter_matched": test_counter,
                    "next_counter": test_counter + 1,
                    "skipped": offset,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        return json.dumps({
            "valid": False,
            "type": "hotp",
            "reason": "Code does not match within the look-ahead window",
            "counter": counter,
            "window": window,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


@mcp.tool()
def generate_secret(length: int = 20, algorithm: str = "sha1", issuer: str = "MEOK", api_key: str = "") -> str:
    """Generate a cryptographically secure random secret for OTP. Returns base32-encoded secret."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if err := _rl():
        return err

    length = max(16, min(length, 64))
    algorithm = algorithm.lower().strip()
    if algorithm not in VALID_ALGORITHMS:
        return json.dumps({"error": f"algorithm must be one of: {VALID_ALGORITHMS}"})

    secret_bytes = secrets.token_bytes(length)
    secret_b32 = _base32_encode(secret_bytes)

    first_totp = _totp(secret_bytes, 30, 6, algorithm)

    return json.dumps({
        "secret": secret_b32,
        "secret_hex": secret_bytes.hex(),
        "length_bytes": length,
        "algorithm": algorithm,
        "issuer": issuer,
        "sample_totp": first_totp,
        "note": "Store this secret securely. Use generate_qr_uri to create a scannable provisioning URI.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@mcp.tool()
def get_qr_uri(secret: str, account: str, issuer: str = "MEOK", algorithm: str = "sha1", digits: int = 6, period: int = 30, api_key: str = "") -> str:
    """Generate an otpauth:// URI for QR code provisioning compatible with Google Authenticator, Authy, etc."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if err := _rl():
        return err

    algorithm = algorithm.lower().strip()
    if algorithm not in VALID_ALGORITHMS:
        return json.dumps({"error": f"algorithm must be one of: {VALID_ALGORITHMS}"})
    if digits not in VALID_DIGITS:
        return json.dumps({"error": f"digits must be one of: {VALID_DIGITS}"})

    secret = secret.strip().upper().replace(' ', '')

    try:
        _base32_decode(secret)
    except Exception:
        return json.dumps({"error": "Invalid base32 secret"})

    label = f"{quote(issuer)}:{quote(account)}"
    params = [
        f"secret={secret}",
        f"issuer={quote(issuer)}",
        f"algorithm={algorithm.upper()}",
        f"digits={digits}",
        f"period={period}",
    ]
    uri = f"otpauth://totp/{label}?{'&'.join(params)}"

    return json.dumps({
        "uri": uri,
        "account": account,
        "issuer": issuer,
        "algorithm": algorithm.upper(),
        "digits": digits,
        "period": period,
        "qr_hint": "Pass this URI to any QR code generator to create a scannable provisioning code.",
        "compatible_apps": ["Google Authenticator", "Authy", "Microsoft Authenticator", "1Password", "Bitwarden"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


if __name__ == "__main__":
    mcp.run()
