# Dynamic DNS Updater

A small Rust daemon that reads the WAN IPv4 address from a TP-Link router and keeps the configured Cloudflare A records synchronized. It runs one reconciliation immediately, then repeats every five minutes.

Production uses the Rust release executable and does not install runtime dependencies at service startup. The obsolete Python implementation was removed after the Rust service completed production verification.

## Configuration

Create a gitignored `.env` in the project root:

```dotenv
TP_LINK_ROUTER_PASSWORD=router-password
CLOUDFLARE_GLOBAL_KEY=global-api-key
CLOUDFLARE_EMAIL=somebody@example.com
```

Cloudflare recommends a scoped API token. When `CLOUDFLARE_API_TOKEN` is present, it takes precedence and the global key/email are not required:

```dotenv
TP_LINK_ROUTER_PASSWORD=router-password
CLOUDFLARE_API_TOKEN=scoped-dns-token
```

Optional settings:

| Variable | Default | Purpose |
|---|---|---|
| `TP_LINK_ROUTER_HOST` | `http://192.168.0.1` | TP-Link router origin |
| `CLOUDFLARE_API_BASE_URL` | `https://api.cloudflare.com/client/v4` | Cloudflare API origin or integration fixture |
| `DYNAMIC_DNS_INTERVAL_SECONDS` | `300` | Daemon reconciliation interval |
| `DYNAMIC_DNS_HTTP_TIMEOUT_SECONDS` | `30` | Per-request timeout |

Secrets are read from the environment, marked sensitive in HTTP headers, and never written to logs.

## Build and run

```powershell
cargo build --release
target\release\dynamic-dns-updater.exe --once
target\release\dynamic-dns-updater.exe
```

`--once` performs one complete cycle and returns a nonzero exit status if the router read or any record fails. The default daemon mode continues after a failed cycle and tries again at the next interval.

On this machine, use the Service Manager at `http://localhost:4000` to start, stop, or restart the registered Dynamic DNS Updater. `run-dynamic-dns-updater-rust.cmd` is the direct Rust launcher used by operational tooling.

## Test

```powershell
cargo test
```

The focused suite covers configuration, TP-Link cryptography, Cloudflare HTTP contracts/retries, reconciliation decisions, zone caching, and scheduler shutdown behavior.
