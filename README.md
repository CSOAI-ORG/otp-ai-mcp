# OTP AI

> By [MEOK AI Labs](https://meok.ai) — Generate and verify TOTP/HOTP codes

## Installation

```bash
pip install otp-ai-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `generate_secret`
Generate a new TOTP secret for an issuer.

**Parameters:**
- `issuer` (str): Issuer name (default: "MEOK")

### `generate_totp`
Generate a time-based one-time password from a secret.

**Parameters:**
- `secret` (str): TOTP secret key

### `verify_totp`
Verify a TOTP code against a secret.

**Parameters:**
- `secret` (str): TOTP secret key
- `code` (str): Code to verify

### `generate_qr_uri`
Generate an otpauth:// URI for QR code enrollment.

**Parameters:**
- `secret` (str): TOTP secret key
- `account` (str): Account identifier
- `issuer` (str): Issuer name (default: "MEOK")

## Authentication

Free tier: 30 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
