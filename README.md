# birdscale

[![CI](https://github.com/tm1000/birdscale/actions/workflows/ci.yml/badge.svg)](https://github.com/tm1000/birdscale/actions/workflows/ci.yml)
[![Image](https://github.com/tm1000/birdscale/actions/workflows/image.yml/badge.svg)](https://github.com/tm1000/birdscale/actions/workflows/image.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Bridge a [Tailscale](https://tailscale.com) tailnet to a [NetBird](https://netbird.io) network — one container, one direction, nothing to change on the NetBird side.

birdscale lets devices that only run Tailscale reach services on a NetBird network. It is one container that runs:

- `tailscaled`, which joins your tailnet and advertises the NetBird routes as a subnet router;
- the `netbird` client, which joins the NetBird network as an ordinary peer (SSO or setup key);
- `birdscaled`, a small supervisor that logs both in, keeps the advertised routes in step with what NetBird gives the peer, owns the firewall (nftables), forwards DNS and serves an optional status page.

Traffic goes one way, tailnet to NetBird. It is source-NATed to the bridge's own NetBird address, so to NetBird it looks like a single peer. Check that your organisation allows bridging the two networks before you deploy this.

```
tailnet device --> tailscale0 --(forward + SNAT)--> wt0 --> NetBird services
```

## Contents

- [birdscale](#birdscale)
  - [Contents](#contents)
  - [Requirements](#requirements)
  - [What it does](#what-it-does)
  - [Quick start](#quick-start)
  - [Image](#image)
  - [Ports \& firewall](#ports--firewall)
  - [Tailscale policy](#tailscale-policy)
  - [Auth key lifetime and OAuth client secrets](#auth-key-lifetime-and-oauth-client-secrets)
  - [DNS and domain resources](#dns-and-domain-resources)
  - [Metrics](#metrics)
  - [Status page and SSO session expiry](#status-page-and-sso-session-expiry)
  - [Firewall notes](#firewall-notes)
  - [IPv6](#ipv6)
  - [The 100.64.0.0/10 caveat](#the-100640010-caveat)
  - [Running next to other subnet routers](#running-next-to-other-subnet-routers)
  - [Upgrading](#upgrading)
  - [Troubleshooting](#troubleshooting)

## Requirements

- Docker with Compose, and `/dev/net/tun`.
- The container needs `NET_ADMIN` and the forwarding sysctls — `compose.yaml` sets all of these.
- The **WireGuard kernel module on the host** (`modprobe wireguard`); NetBird uses kernel WireGuard on `wt0`.
- Outbound HTTPS to the Tailscale control server and your NetBird management, signal and relay endpoints.
- Optionally, inbound UDP 41641 and 51820 through any firewall in front of the host. Without them both daemons fall back to relays.

> [!NOTE]
> If the host already runs `tailscaled` on UDP 41641, change the host side of the port mapping with `TS_HOST_PORT` (see `.env.example`).

## What it does

- **Routes follow NetBird.** The peer network and every CIDR NetBird sends to this peer are advertised, kept in sync continuously, and pruned when NetBird removes them.
- **Domain resources work.** NetBird creates a `/32` route on demand when a domain resource is resolved. birdscale watches NetBird's routing table, advertises those `/32`s, pre-resolves every non-wildcard domain resource so the route exists before the first client asks, and runs a DNS forwarder so tailnet clients can resolve NetBird-only names.
- **Firewall.** Forwarding is default-deny except tailnet to NetBird. Inbound traffic arriving on `tailscale0` and `wt0` is dropped except ICMP, replies, the status page and DNS. Other interfaces are not filtered.
- **Status page** (optional) on the bridge's Tailscale IP: health, route sync, DNS counters, pre-warm results, warnings, and a NetBird re-login button.

## Quick start

The repository ships a ready `compose.yaml`; all settings are environment variables:

```sh
cp .env.example .env    # then set at least NB_MANAGEMENT_URL and a tagged TS_AUTHKEY
docker compose pull && docker compose up -d    # published image
docker compose logs -f                          # first login URLs appear here
```

For a local build instead:

```sh
BIRDSCALE_IMAGE=birdscale:local docker compose build
BIRDSCALE_IMAGE=birdscale:local docker compose up -d
```

`compose.yaml` provides the `NET_ADMIN` capability, `/dev/net/tun`, the forwarding sysctls, the state volumes (`ts-state` for `/var/lib/tailscale`, `nb-state` for `/etc/netbird`) and the UDP port mappings.

All settings are environment variables; `.env.example` lists them with comments. The interesting ones:

| Variable | Purpose |
|----------|---------|
| `NB_MANAGEMENT_URL` | Required: NetBird cloud or self-hosted management URL |
| `TS_AUTHKEY` / `TS_TAGS` | Tailscale auth key (or OAuth client secret) and its tag |
| `NB_SETUP_KEY` | NetBird setup key (empty = SSO login) |
| `BS_ROUTES` | Replace the computed advertised routes |
| `BS_ADVERTISE_EXIT_NODE` | Also advertise `0.0.0.0/0` and `::/0` |
| `BS_WEBUI_PORT` / `BS_WEBUI_ALLOW` | Enable and restrict the status page (and `/metrics`) |
| `BS_DNS`, `BS_DNS_DOMAINS`, `BS_DNS_ROUTE_WAIT`, `BS_DOMAIN_REFRESH` | DNS forwarder and domain-resource pre-warm |
| `BS_SESSION_WARN` | SSO-expiry warning window |
| `BS_LOG_LEVEL` | `debug` for pre-warm and DNS detail |

First start without credentials: the NetBird SSO URL and the Tailscale login URL appear in the logs, and on the status page once Tailscale is up. With `NB_SETUP_KEY` and `TS_AUTHKEY` set there is nothing to approve.

## Image

The published image is `ghcr.io/tm1000/birdscale` (linux/amd64 and linux/arm64), with SBOM and provenance attestations. The same tags can also be published to Docker Hub when the repository is configured for it (see the comment at the top of `.github/workflows/image.yml`). Tags: `X.Y.Z`, `X.Y` and `X` (the bare `X` only from 1.0), `latest` (newest release), `main` and `sha-<short>` (the main branch).

> [!NOTE]
> Pin a version or a digest in production, not `latest`.

`compose.yaml` keeps `build: .`, so a local build always works. Local builds report version `dev` unless you set `BIRDSCALE_VERSION` (the `VERSION` build arg); the version is stamped into the binary and shown in the start-up log line, on the status page and in `birdscale_build_info`.

## Ports & firewall

| Port | Where | Purpose |
|------|-------|---------|
| UDP 41641 (`TS_PORT`) | host, inbound | Tailscale direct connections (without it, DERP relays) |
| UDP 51820 (`NB_PORT`) | host, inbound | NetBird direct connections (without it, NetBird relay) |
| TCP/UDP 53 | Tailscale IP, tailnet only | DNS forwarder (`BS_DNS`) |
| TCP `BS_WEBUI_PORT` | Tailscale IP, tailnet only | status page and `/metrics` |
| TCP 9180 (`BS_HEALTH_PORT`) | container loopback | `/healthz` and the Docker healthcheck |

Nothing else is published. Inside the container, inbound on `tailscale0` and `wt0` is dropped except ICMP, replies, the status page and DNS (see [firewall notes](#firewall-notes)).

## Tailscale policy

The bridge joins with a tag, so the tailnet policy must define it and approve its routes automatically. In the policy file:

```jsonc
{
  "tagOwners": {
    "tag:birdscale": ["autogroup:admin"]            // or a group of yours
  },
  "autoApprovers": {
    "routes": {
      // Cover the NetBird peer network, every route NetBird sends, and the
      // on-demand /32s of domain resources. A covering prefix auto-approves
      // anything inside it, so use a prefix that contains them all.
      "10.0.0.0/8":     ["tag:birdscale"],
      "172.16.0.0/12":  ["tag:birdscale"],
      "192.168.0.0/16": ["tag:birdscale"]
    }
  },
  "acls": [
    // Who may use the bridge. Port 53 is the DNS forwarder, the web port the status page.
    {"action": "accept", "src": ["group:netbird-users"], "dst": ["tag:birdscale:53", "10.0.0.0/8:*"]}
  ]
}
```

Use the real ranges of your NetBird network. Domain resources can resolve to any address (including public ones), so the `autoApprovers` prefix has to cover wherever they land; a broad prefix is simplest. A `/32` that is not covered is advertised but waits for manual approval in the admin console, and clients will not reach it until you approve it.

Create the auth key (`TS_AUTHKEY`) with the tag `tag:birdscale`, and make it pre-approved if the tailnet requires device approval. Set `TS_TAGS=tag:birdscale` to match.

## Auth key lifetime and OAuth client secrets

- **Tagged nodes don't expire.** A node registered with a tag has key expiry disabled, so once the bridge has registered it never needs to re-authenticate. Its identity lives in the `/var/lib/tailscale` volume. The auth key only matters at first registration, or if that volume is lost.
- **Auth keys expire after at most 90 days.** For hands-off redeploys (a fresh volume, a rebuilt host) use a Tailscale OAuth client secret as `TS_AUTHKEY` instead; it doesn't expire.
  1. In the admin console go to **Settings**, **OAuth clients**, and create a client with the `auth_keys` scope (write) and the tag `tag:birdscale`.
  2. Set, in `.env`:

     ```
     TS_AUTHKEY=tskey-client-XXXX?ephemeral=false&preauthorized=true
     TS_TAGS=tag:birdscale
     ```

     Tags are required with OAuth secrets (birdscaled refuses to start without `TS_TAGS`). Keep `ephemeral=false`, otherwise the node is removed when it goes offline. `preauthorized=true` skips device approval.
  3. If your `.env` is read by a tool that treats `&` or `?` specially (a shell `source`, for example), quote the value. Docker Compose's `env_file` takes it literally.

On start the Tailscale CLI exchanges the secret for a one-off auth key and registers the node.

## DNS and domain resources

A NetBird domain resource only becomes reachable after NetBird's resolver has looked the name up: that lookup is what installs its `/32` route. The bridge pre-warms every non-wildcard domain resource at start-up and every `BS_DOMAIN_REFRESH`, then advertises the resulting `/32`s. NetBird reports itself Connected a few seconds before its resolver answers, so the first pre-warm after every (re)connect waits for the resolver (a probe query with short backoff, up to 30 s, then it carries on regardless). Failures in the 30 s after the resolver is up log at DEBUG; a WARN means a lookup is still failing after that, or the resolver never answered.

You may not need split DNS at all. If your domain resources resolve to the same internal IPs in public DNS (for example internal names published in Cloudflare), pre-warm already creates the routes and clients can use their normal resolver — and name resolution doesn't depend on the bridge being up.

Set up split DNS only when names exist **only** in NetBird DNS, or for **wildcard** resources, which pre-warm can't cover:

1. Set `BS_DNS=true` (the default). The bridge answers DNS on UDP/TCP port 53, on its Tailscale IP only, and forwards to NetBird's resolver.
2. In the Tailscale admin console go to **DNS**, **Add nameserver**, **Custom**. Enter the bridge's Tailscale IP (shown on the status page and in the admin console), tick **Restrict to domain** (split DNS) and enter each NetBird domain, for example `example.internal`.
3. Optionally set `BS_DNS_DOMAINS=example.internal` so the bridge refuses everything else (REFUSED) instead of acting as an open resolver for the whole tailnet.
4. Make the ACL allow your clients to reach `tag:birdscale:53`.

When a client resolves a domain resource, the answer is held for up to `BS_DNS_ROUTE_WAIT` (1.5 s by default) while the new `/32` is advertised, so the first connection usually works. Wildcard resources (`*.example.internal`) cannot be resolved ahead of time; they are learned from real queries, so the first lookup of each new name takes a little longer.

## Metrics

With `BS_WEBUI_PORT` set, `GET /metrics` serves Prometheus metrics on the same Tailscale-IP-only listener and with the same `BS_WEBUI_ALLOW` allow-list as the status page (without the port there is no endpoint). Go and process metrics are included; everything else is prefixed `birdscale_`: build info, health (overall and per check), Tailscale and NetBird states, NetBird peers and SSO expiry, routes by state and origin, route sync changes, pre-warm state and failures, DNS forwarder counters, nftables rule counters, address overlaps and re-login attempts. Labels are bounded (no client addresses, no query names).

To scrape from a Prometheus on the tailnet, give it a tag, allow the tag and the ACL:

```
# .env
BS_WEBUI_PORT=8080
BS_WEBUI_ALLOW=admin@example.internal,tag:prometheus
# ACL: {"action": "accept", "src": ["tag:prometheus"], "dst": ["tag:birdscale:8080"]}

# prometheus.yml
- job_name: birdscale
  static_configs:
    - targets: ["birdscale.example-tailnet.ts.net:8080"]   # or the bridge's Tailscale IP
```

The scraper is subject to the page's rate limit (about 1 request per second per client), which normal scrape intervals stay well under. Useful alerts: `birdscale_healthy == 0`, `birdscale_netbird_session_expiry_timestamp_seconds - time() < 86400`, `birdscale_prewarm_domains{state="retrying"} > 0` for several minutes.

## Status page and SSO session expiry

NetBird SSO peers have a session that expires, after 7 days by default (a setup-key peer has none). When it expires the bridge stops carrying traffic until someone logs in again.

- birdscale warns in the log and on the status page when the session is within `BS_SESSION_WARN` (24 h) of expiring.
- The status page has a button. Before expiry it renews the session without dropping the tunnel (`netbird login --extend`); after expiry it starts a fresh login (`netbird up`). Either way the page then shows a login URL to open in a browser.
- The button is the only state-changing action. It requires the `BS_WEBUI_ALLOW` allow-list and a CSRF token. Without `BS_WEBUI_PORT` there is no page: watch the logs for the login URL and restart the container, or run `docker exec birdscale netbird login --extend --no-browser`.

## Firewall notes

birdscale installs the nftables table `inet birdscale`. Its input chain only acts on traffic arriving on `tailscale0` and `wt0`: it accepts replies and ICMP, the status page port and DNS (on `tailscale0` only) and drops other new inbound. NetBird's own needs are met by this: its WireGuard and relay traffic uses the container's normal interface, its DNS and SSH redirects are local (output-side) rules, and a NetBird *routing peer* DNS forwarder or SSH server would need inbound on `wt0`, which this bridge is not and has disabled. The table is removed on shutdown.

## IPv6

The bridge is dual-stack where the pieces allow. The firewall is an `inet` table, so forwarding, masquerade, MSS clamping and the input rules apply to both families; the DNS forwarder and status page bind every Tailscale address, v6 included; learned `/128` routes, v6 CIDRs from NetBird and the NetBird v6 peer network (`netbirdIpv6`) are advertised; and the overlap check covers Tailscale's `fd7a:115c:a1e0::/48`.

Whether NetBird gives its peers IPv6 depends on your NetBird account and client version, which you may not control. The bridge forwards IPv6 when NetBird provides it and does nothing special otherwise. Tailnet clients still need the usual IPv6 route to the bridge (auto-approved like the v4 ones, so add the v6 prefixes to `autoApprovers`). This was tested with synthetic data in unit tests only, not against a live dual-stack NetBird.

## The 100.64.0.0/10 caveat

> [!WARNING]
> Tailscale addresses come from `100.64.0.0/10`, and NetBird's default peer range is also inside that block. If your NetBird network uses it, tailnet devices and NetBird peers can share addresses and the bridge cannot tell them apart. birdscale warns (log and status page) when any tailnet address falls inside an advertised route. Fix it by re-addressing the colliding tailnet devices or restricting the tailnet with an `ipPool`. Some Tailscale clients also refuse subnet routes inside `100.64.0.0/10`, so NetBird *peer addresses* may be unreachable through the bridge even when everything is configured correctly. Services behind NetBird routes in ordinary private ranges (10/8, 172.16/12, 192.168/16) are not affected.

`TS_NETFILTER_MODE` stays `off` for the same reason: tailscaled's own rules drop forwarded traffic from `100.64.0.0/10`. birdscale owns the forwarding rules instead.

## Running next to other subnet routers

Another router (a second bridge, tailguard, a plain subnet router) may advertise a range that overlaps yours. Tailscale clients send traffic to the most specific matching route, so the bridge's `/32`s and narrow CIDRs win over a broader route from elsewhere, and a broader route of the bridge's doesn't hijack a narrower one. For identical prefixes Tailscale picks one router (and fails over between them), so keep ranges distinct or accept that. The bridge never accepts routes from the tailnet (`--accept-routes=false`, enforced every poll), so another router's overlapping ranges can't pull NetBird-bound traffic back into the tailnet.

## Upgrading

1. Read the release notes. Pull the new image (`docker compose pull`) or rebuild, then `docker compose up -d`. State lives in the two volumes, so logins survive.
2. Tailscale and NetBird are pinned in the `Dockerfile` (`TAILSCALE_VERSION`, `NETBIRD_VERSION`) and Renovate opens PRs for them; the Tailscale bump also updates the `tailscale.com` Go module, and CI checks they agree. The tarball checksums are fetched from the vendors at build time and verified in the same step, so a version bump needs no checksum edits. (They come from the same origin as the tarball, so this catches corruption and bad mirrors, not a compromised release.)
3. The container restarts briefly: the tailnet loses the bridge for roughly 10 to 20 s.
4. Re-check after a NetBird bump that its routing table (7120) and fwmark do not collide with Tailscale's (see `ip rule`).

## Troubleshooting

Start with `docker logs birdscale` (add `BS_LOG_LEVEL=debug` for pre-warm and DNS detail). Then:

- `docker exec birdscale birdscaled health` prints the checks as JSON and exits 1 when unhealthy (it queries `/healthz` on the loopback port `BS_HEALTH_PORT`).
- The status page at `http://<bridge tailscale ip>:<BS_WEBUI_PORT>/` shows each check, the routes with approval state, pre-warm results, warnings and the login URLs.

Common failures:

- **Tailscale `NeedsMachineAuth`**: the tailnet requires device approval. Approve the bridge in the admin console, or use a pre-approved auth key.
- **Tag not permitted / auth key rejected**: define `tag:birdscale` under `tagOwners`, create the key with that tag, and set `TS_TAGS` to match.
- **Routes advertised but not approved**: the `autoApprovers` prefix doesn't cover them (the status page lists each route as pending). Widen the prefix or approve in the admin console.
- **NetBird `NeedsLogin` or `SessionExpired`**: open the login URL from the log or the status page button. Use `NB_SETUP_KEY` to avoid expiry entirely.
- **Address overlap warning (100.64.0.0/10)**: see [the caveat above](#the-100640010-caveat); re-address colliding devices or use an `ipPool`.
- **A domain resource name doesn't resolve or connect on the first try**: check the pre-warm section of the status page and the `dns:` log lines; wildcard resources are only learned from real queries through the forwarder.

> [!NOTE]
> Taildrop (and any other peerapi service) on the bridge is blocked by the input filter. That is intended: the bridge is a router, not a file target. Send files to a real device instead.