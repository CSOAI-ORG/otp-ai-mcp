<div align="center">

# Otp Ai MCP

**MCP server for otp ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-otp-ai-mcp)](https://pypi.org/project/meok-otp-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Otp Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `generate_otp` | Generate a one-time password from a base32 secret. Supports TOTP (time-based) an |
| `verify_otp` | Verify a one-time password against a secret. Window parameter allows for clock d |
| `generate_secret` | Generate a cryptographically secure random secret for OTP. Returns base32-encode |
| `get_qr_uri` | Generate an otpauth:// URI for QR code provisioning compatible with Google Authe |

## Installation

```bash
pip install meok-otp-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "otp-ai": {
      "command": "python",
      "args": ["-m", "meok_otp_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
