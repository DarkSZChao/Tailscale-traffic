# Tailscale Traffic Dashboard

**English** | [简体中文](README.zh-CN.md)

A lightweight traffic dashboard for a Tailscale Linux exit node. It tracks upload, download, and monthly traffic usage by friend and device.

![Python](https://img.shields.io/badge/Python-3.12-3776AB)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)

## Why this project

Tailscale's official [Network flow logs](https://tailscale.com/docs/features/logging/network-flow-logs) include byte counts for exit-node traffic, but they are currently available only on the Premium and Enterprise plans, and the admin console does not provide a real-time usage dashboard.

Tailscale Traffic Dashboard does not depend on paid APIs. It automatically discovers Tailscale IPs and counts their traffic in the VPS's Linux forwarding chains, then maps each IP to an account and device through the `tailscaled` LocalAPI WhoIs endpoint. It can even identify friends from external tailnets whose devices do not appear in the regular `tailscale status` output:

- Track upload and download separately;
- Group multiple devices belonging to the same friend by account;
- Distinguish devices in your tailnet from external devices connected through node sharing;
- Set monthly limits for an entire user or an individual device and automatically block traffic when a limit is reached;
- Aggregate visited sites, approximate connection counts, uploads, and downloads by device and date;
- Persist daily data in SQLite and summarize usage by calendar month;
- Configure a monthly traffic allowance and view a projected end-of-month total;
- Assign custom account aliases from the dashboard;
- Use revocable browser sessions, optionally remember a device for 30 days, and manage signed-in devices;
- Review bounded login, configuration, policy, and collector-status audit logs;
- Make a best-effort attempt to identify domains from exit-node DNS, HTTP Host headers, and TLS SNI;
- Store only daily aggregates by domain or destination IP for website details, without retaining URLs, request contents, or individual connections.

## Prerequisites

- A Linux VPS with Tailscale running on the host and configured as an exit node;
- Kernel networking mode with a `tailscale0` interface;
- Docker Engine and Docker Compose v2;
- The host's Tailscale socket available at `/var/run/tailscale/tailscaled.sock`;
- Conntrack traffic accounting enabled in the kernel;
- An exit node used primarily for internet access. If the same node also advertises subnet routes, subnet traffic forwarded through `tailscale0` will also be counted.

## Deployment

```bash
git clone <your-repository-url>
cd <repository-directory>
```

Website traffic details require conntrack byte accounting. Before the first deployment, run:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

To preserve the setting after the VPS restarts, add the following to
`/etc/sysctl.d/99-tailscale-traffic.conf`:

```text
net.netfilter.nf_conntrack_acct=1
```

Then start the services:

```bash
docker compose up -d --build
```

When upgrading from the older single-container version, remove the old container during the first migration. The data directory will not be deleted:

```bash
docker compose down --remove-orphans
docker compose up -d --build
```

Compose starts two independent containers:

- `collector` runs continuously and handles traffic collection and quota enforcement;
- `dashboard` serves the control panel and can be updated or restarted independently.

The dashboard container listens on port 8000 internally and is published on port **4656** on all host addresses.
Use a firewall to restrict access to trusted sources:

```text
http://<your-VPS-Tailscale-IP>:4656
```

For example, use UFW to allow access only through the Tailscale interface:

```bash
sudo ufw allow in on tailscale0 to any port 4656 proto tcp
```

The first time you open the dashboard, you will be prompted to set a password. No username is required, and `.env` is no longer used.
Only a secure password hash and hashed session tokens are stored in `traffic.db`. By default, login lasts for the current browser session. Select “Remember this device” to keep it for 30 days. The Settings page can revoke one device, sign out every device, or change the password; changing the password invalidates every other session.

Do not expose the unencrypted port 4656 directly to the public internet. Plain HTTP does not encrypt the password submitted during login. When you access the dashboard through a Tailscale IP, the connection is encrypted by Tailscale.

## Checking status

```bash
docker compose ps
docker compose logs -f --tail=100
```

When everything is working, the sidebar shows “Collector healthy,” its uptime, the latest update time, and the project version. After the first startup, traffic can only be recorded from the point when the application creates its counting rules; earlier traffic cannot be recovered.

If the page reports a collector error, check the following first:

```bash
ls -l /var/run/tailscale/tailscaled.sock
ip link show tailscale0
docker compose logs collector --tail=100
```

## Data and upgrades

Persistent files are stored at:

```text
./config.yaml        # Non-sensitive runtime settings
./data/traffic.db    # Traffic data, rules, password hash, and sessions
./data/log.db        # Login, operation, and collector-status audit logs
```

The collector and dashboard use file locking to safely read and write `config.yaml`, so neither process will read a partially written configuration. Traffic and authentication data are shared through SQLite WAL. Before making a backup, stop the services and copy both the entire `data` directory and the configuration file from the repository root:

```bash
docker compose stop
cp -a data data.backup
cp -a config.yaml config.yaml.backup
docker compose start
```

Upgrade all services:

```bash
git pull
docker compose up -d --build
```

Update only the dashboard without interrupting collection:

```bash
docker compose up -d --build dashboard
```

Stopping the containers does not delete data, and the counting chains on the host remain in place. After the collector restarts, it continues calculating differences from the existing counters. If a host reboot resets the counters to zero, the application automatically continues accumulating from the new values. Changes to limits made in the dashboard are applied on the collector's next cycle, normally within about 10 seconds.

The monthly traffic allowance, collection interval, website-record retention period, and reporting time zone are managed on the Settings page and stored in `./config.yaml`. The reporting time zone defaults to UTC and can be changed when calendar-day aggregation should follow another locale. Website-detail collection is always enabled.
The collector automatically reloads updated settings. Authentication data remains exclusively in `traffic.db`. Audit logs use a separate SQLite WAL database at `data/log.db`; timestamps are stored in UTC and displayed in the browser's local time zone. The audit table retains at most 5,000 entries and can be searched, filtered by UTC date, refreshed, or cleared from the Logs page. On the first upgraded start, audit entries created by the earlier combined-database version are copied to `log.db` before the old table is removed from `traffic.db`. When upgrading from an older version, runtime settings stored in the database are automatically migrated to YAML, after which the old configuration table is removed.

Website details are retained for 180 days by default and aggregated by date, device, and domain. URLs, request paths, and individual connections are not stored.

User and device website activity defaults to “Past 1 day,” a rolling 24-hour window independent of the reporting time zone, and can also be viewed by date. Short-term website details are aggregated into 15-minute buckets and retained for approximately 25 hours. Visit times are displayed by the browser in the viewer's local time zone. After an upgrade, short-term details begin accumulating from zero.

The device list hides nodes whose keys have expired and whose usage for the selected month is zero. Enable “Show expired devices” to view these historical nodes. Expired devices with traffic in the selected month are always shown and retain an `Expired` badge.

Device lists in user cards are collapsed by default. Click the small triangle to the left of a user to expand or collapse the list. Automatic dashboard refreshes preserve the current expanded state.

Download, upload, and total values for users and devices are shown as “Past 1 day / selected month.” Past-day statistics use 5-minute buckets and are retained for approximately 25 hours without storing individual connection details. After an upgrade, this statistic begins accumulating from zero; the current month's cumulative totals are unaffected.

Tailscale hides the real hostnames of externally shared nodes. When no device alias is configured, the dashboard uses the last octet of the IPv4 address to display a name such as `SHARED-DEVICE-xxx`. Device aliases are stored in `traffic.db` using the stable device ID. Clear an alias to restore the default name.

Domain identification uses three lightweight sources:

- Cache exit-node DNS responses for up to five minutes as a shared IP-to-domain candidate mapping;
- Read the `Host` request header from new plaintext HTTP connections;
- Read the unencrypted SNI field from the TLS ClientHello of new TCP HTTPS connections.

The packet-capture socket has a kernel filter that passes only DNS responses and the initial packets that may contain HTTP Host or TLS SNI metadata to Python. Packets transferred after video and download connections are established do not enter the parsing pipeline.
Both connection-level domain mappings and DNS mappings use bounded in-memory caches; raw packets are never written to disk.

## Accounting methodology

- “Upload”: IP-layer bytes entering the exit node from a friend's device, ready to be forwarded to the public internet;
- “Download”: IP-layer bytes in public-internet responses, ready to be forwarded from the exit node to a friend's device;
- “Total”: upload + download;
- VPS providers may bill at the link layer, count only outbound traffic, or use decimal GB instead of GiB, so dashboard totals may differ slightly from provider invoices;
- An individual counter is created only after a device first appears in the exit node's state;
- A user limit applies to the current-month total of all that user's devices. Device limits begin accumulating per device after this version is deployed;
- When a limit is reached, both IPv4 and IPv6 traffic for the device is blocked. Manual unlock bypasses the limit only for the current month, and the rule is enforced again automatically in the next month;
- Website visit counts approximate new connections and do not represent browser page views;
- DNS, HTTP Host, and TLS SNI identification are all best effort. QUIC/HTTP3, ECH, VPN-over-VPN connections, fragmented handshakes, and direct IP connections may still show only the destination IP;
- A CDN IP may serve multiple domains, so the shared DNS fallback may occasionally show another domain that was recently resolved to the same IP. TLS SNI or HTTP Host observed on the same connection takes priority over shared DNS;
- Website details depend on periodic conntrack snapshots, so identified website traffic may be lower than the device's total traffic.

## Security notes

Only the `collector` container uses host networking and the `NET_ADMIN` and `NET_RAW` capabilities. These permissions are required to read traffic, capture DNS and connection-handshake metadata, maintain counting rules, and enforce quota blocks.
The `dashboard` uses a regular bridge network and cannot access the host firewall or Tailscale socket. No device is blocked unless a limit rule has been configured. The collector creates the following dedicated chains and sets:

- `TSM_UPLOAD`
- `TSM_DOWNLOAD`
- `tsm_upload4` / `tsm_download4`
- `tsm_upload6` / `tsm_download6`
- `tsm_block4` / `tsm_block6`
- `tsm_block4_next` / `tsm_block6_next` (used for atomic block-list updates)

Build images only from trusted sources and trusted repository code.
