# AGENTS.md

## Project overview

birdscale is a Docker container that bridges a **Tailscale** tailnet to a **NetBird**
network, so devices that only run Tailscale can reach NetBird services. It's the same
idea as [juhovh/tailguard](https://github.com/juhovh/tailguard), with NetBird in place
of a plain WireGuard tunnel.

- **Direction:** tailnet → NetBird only. NetBird peers can't open connections into the
  tailnet.
- **The bridge is an ordinary NetBird peer**, logged in via SSO or a setup key. It
  assumes no admin access on the NetBird side. To NetBird, all bridged traffic comes from
  this one peer (SNAT).
- **One container holds:**
  - the official `tailscaled` on kernel TUN `tailscale0`;
  - the official `netbird` client on kernel WireGuard `wt0`;
  - `birdscaled`, a Go supervisor (this repo) that drives both and owns forwarding,
    routes, DNS and the status page.

Packet path: tailnet device → `tailscale0` → kernel forward + masquerade → `wt0` →
NetBird.

## Layout

- `cmd/birdscaled`: entrypoint. `run` (default) and the `health` subcommand used by the
  Docker HEALTHCHECK.
- `internal/config`: env loading and validation. It holds the redacted config dump.
  Every `TS_*`, `NB_*` and `BS_*` variable is defined here.
- `internal/supervisor`: process supervision of both daemons, and the main loop that
  wires everything together.
- `internal/tailscale`: LocalAPI wrapper (status, prefs, `WhoIs`), `tailscale up`
  login, pref drift correction.
- `internal/netbird`: `netbird status --json` parsing, plus the login/renew flows
  (`netbird up --no-browser`, `netbird login --extend`).
- `internal/routes`: pure `Compute` for the advertised route set, with route origins
  and `Diff`.
- `internal/rtwatch`: netlink watcher for NetBird's routing table 7120 (`/32` and `/128`
  routes on `wt0`).
- `internal/routesync`: debounced reconciler that applies the desired routes to
  Tailscale prefs.
- `internal/prewarm`: resolves NetBird domain resources through NetBird's resolver so
  their `/32` routes exist before clients need them. Retries with backoff. Waits for the
  resolver to answer a probe before the first lookup after (re)connect; failures in the
  start-up grace window log at DEBUG.
- `internal/dnsfwd`: optional DNS forwarder on the Tailscale IP that forwards to
  NetBird's resolver.
- `internal/nft`: the `inet birdscale` nftables table (forward, SNAT, MSS clamp, input
  filter), rendered from a template.
- `internal/overlap`: warns when tailnet IPs fall inside advertised routes.
- `internal/health`: health evaluation, the loopback `/healthz` endpoint and its probe.
- `internal/status`: shared snapshot store, read by the web page and metrics.
- `internal/metrics`: private Prometheus registry; one collector turns the status snapshot
  into `birdscale_*` metrics at scrape time. Served at `/metrics` by `internal/web`.
- `internal/version`: `Version`, stamped with `-ldflags -X` from the `VERSION` build arg.
- `internal/web`: read-only status page plus the single POST (`/netbird/relogin`), with
  `WhoIs` auth, CSRF and rate limiting.
- `Dockerfile`: builds `birdscaled` and installs the pinned, checksum-verified
  tailscale and netbird release tarballs.
- `compose.yaml` and `.env.example`: the deployment example.
- `README.md`: the user-facing docs.

## Setup and build

Requires Go (version in `go.mod`) and Docker with buildx.

```sh
go build ./...
docker build -t birdscale:local .
cp .env.example .env    # fill in TS_AUTHKEY, NB_MANAGEMENT_URL, ...
docker compose up -d --build
docker compose logs -f
docker exec birdscale birdscaled health
```

Running it needs `NET_ADMIN`, `/dev/net/tun`, the sysctls in `compose.yaml`, and the
WireGuard kernel module on the host. A local run without real keys is useful for
smoke-testing start-up and shutdown:
- set `TS_LOGIN_SERVER=http://127.0.0.1:9` so it never contacts the real Tailscale
  control plane;
- use a dummy `NB_MANAGEMENT_URL`;
- don't publish UDP 41641 if the host already runs `tailscaled`.

## Testing

```sh
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
go test ./internal/prewarm -run TestName -v                 # focus on one test
BS_LIVE_NETLINK=1 go test ./internal/rtwatch -run Live -v   # needs CAP_NET_ADMIN; run in a throwaway container
```

- staticcheck runs in CI at the version pinned in `.github/workflows/ci.yml`. Use the
  same version locally via `go run honnef.co/go/tools/cmd/staticcheck@<version> ./...`.
- Tests sit next to the code (`*_test.go`). Keep logic in pure functions and inject
  fakes. Existing tests use fake resolvers, fake clocks/sleep, fake `WhoIs` and fake CLI
  scripts.
- Use only synthetic network data in tests and docs: `10.99.0.0/16`,
  `example.internal`, documentation prefixes. Never real company IPs or domains.
- Behaviour that needs a real tailnet and NetBird (logins, route approval, SSO renew)
  is verified by deploying to a test host. Unit tests can't cover it, so say so in your
  report when you change it.

## Code style

- Standard Go: `gofmt`, small packages under `internal/`, no global state.
- Logging uses `log/slog`, with lowercase messages prefixed by subsystem (`routes:`,
  `prewarm:`, `dns:`, `netbird:`, `tailscale:`, `nftables:`, `web:`).
- **Log levels:** INFO for state changes, WARN only for things a user should act on,
  DEBUG for retries.
- Errors are wrapped with context. Don't panic in long-running loops. Every goroutine
  stops on context cancel.
- Pin new dependencies to exact versions. `tailscale.com` in `go.mod` must equal
  `TAILSCALE_VERSION` in the `Dockerfile`, so bump them together.

## Invariants (don't break these)

- **The bridge never accepts tailnet routes** (`RouteAll=false`). Other subnet routers
  may advertise overlapping ranges, and accepting them would loop NetBird-bound traffic
  back into the tailnet. Pref drift correction enforces this.
- **Tailscale netfilter mode defaults to `off`,** and birdscale owns the forwarding
  rules.
  - In `on` mode, tailscaled drops forwarded traffic with a `100.64.0.0/10` source going
    out `tailscale0`. That breaks NetBird accounts on the CGNAT range.
  - It's a `tailscale up/set` pref, not a `tailscaled` flag.
- **`--accept-dns=false` on Tailscale.** NetBird owns the container's resolver.
- **Only touch the `inet birdscale` nft table.**
  - Never edit NetBird's or Tailscale's own tables.
  - The input chain only filters `tailscale0` and `wt0`, never `eth0` or `lo`.
  - The table is removed on shutdown.
- **Listeners (status page, metrics, DNS) bind only to the bridge's Tailscale IPs.**
  - Every HTTP request is authorised with LocalAPI `WhoIs` against `BS_WEBUI_ALLOW`.
  - The only state-changing endpoint is `POST /netbird/relogin`, protected by CSRF and
    an Origin check. Don't add others casually.
- **Secrets** (`TS_AUTHKEY`, `NB_SETUP_KEY`) never appear in logs or argv.
  - They're passed via 0600 temp files (`--auth-key=file:`, `--setup-key-file`).
  - They're unset from birdscaled's environment after loading.
- **NetBird state lives in `/etc/netbird`** (`NB_STATE_DIR`, which the Dockerfile sets).
  NetBird ≥0.82 otherwise defaults to `/var/lib/netbird`.
- **The advertised NetBird peer network is the prefix from `netbirdIp`.** Never assume a
  `/16`.

## NetBird and Tailscale facts the code relies on

- **NetBird status:** read with `netbird status --json`. `-d` and `--json` are mutually
  exclusive.
  - Received routes are in `peers.details[].networks`, which mixes CIDRs, bare IPs and
    domain names.
  - SSO expiry is `sessionExpiresAt`.
- **NetBird routing:** table 7120, rule pref 110, fwmark `0x1bd00`.
  - Domain resources become `/32 dev wt0` routes in table 7120 only after a lookup
    through NetBird's resolver (the peer's NetBird IP, port 53).
  - The resolver answers a few seconds after the daemon reports Connected.
- **Tailscale routing:** table 52, prefs 5210–5270, fwmarks `0x40000`/`0x80000` under
  mask `0xff0000`. Re-check for collisions with NetBird on version bumps.
- **NetBird login and renewal:**
  - Before expiry, `netbird login --extend --no-browser` renews the session and keeps
    the tunnel up.
  - After expiry, or when never logged in, use `netbird up --no-browser`.
  - A plain `up` while Connected does nothing.
- **Tailscale login:**
  - Tagged nodes have key expiry disabled.
  - OAuth client secrets (`tskey-client-…?ephemeral=false&preauthorized=true`) work as
    `TS_AUTHKEY`, but require `TS_TAGS`.

## Build and deployment

- The image is multi-stage:
  1. build `birdscaled`;
  2. fetch the tailscale and netbird tarballs for `TARGETARCH` and verify their
     checksums;
  3. `debian:trixie-slim` runtime.
- `ENTRYPOINT ["birdscaled"]`, with a HEALTHCHECK that runs `birdscaled health`.
- `.github/workflows/` runs CI and publishes the multi-arch image to GHCR. Renovate
  (`renovate.json`) bumps Go modules, base images, the pinned tailscale/netbird releases
  and staticcheck. Dependabot (`.github/dependabot.yml`) bumps the GitHub Actions. Keep
  actions pinned by full commit SHA with a `# vX.Y.Z` comment; Dependabot updates both.
- Deploy with `compose.yaml`. Logins persist in the `ts-state` and `nb-state` volumes.

## Contributing

- Keep `README.md` user-facing and generic (no deployment-specific hosts, IPs or
  domains). Put agent and developer context here.
- Before proposing a change, run `gofmt -l .`, `go vet ./...`, `go test -race ./...`
  and staticcheck, and `docker build .` if the Dockerfile or dependencies changed.
- Add or update tests for any behaviour you change. Update `.env.example` and
  `README.md` when you add or change a config variable.

## Known gaps

- **No end-to-end integration test in CI.** The idea is a Compose stack with headscale
  plus a self-hosted NetBird, testing tailnet → bridge → NetBird traffic. CI covers only
  gofmt, vet, `go test -race`, staticcheck and a docker build. Live behaviour (logins,
  route approval, SSO renew) was verified by hand on a test host.
- **arm64:** `image.yml` builds and publishes the multi-arch image (amd64 + arm64), but
  the arm64 image hasn't been run on real arm64 hardware.
- **IPv6:** unit-tested only. The format of `netbirdIpv6` with a dual-stack NetBird
  account is unverified; the parser accepts it with or without a prefix length.
- **Publishing doesn't wait for CI:** `image.yml` doesn't depend on `ci.yml`. To gate it,
  make `ci.yml` a reusable `workflow_call` workflow.
- **Tailscale OAuth client secrets** as `TS_AUTHKEY` are verified from source and unit
  tests only, not with a live registration.
