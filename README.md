# IPsec S2S Manager

Interactive Bash management for route-based IKEv2/IPsec tunnels, WireGuard remote access, UFW, packet-path diagnostics and cron jobs on Debian 13.

The project is intended for administrators who want guided, reviewable changes without hiding the underlying Linux configuration. It uses strongSwan/swanctl, VTI interfaces, routing table 220 and standard Debian services. Existing installations can be discovered and reviewed before the manager takes ownership.

> All addresses and names in this documentation are fictional examples. The real interface uses terminal colors; code blocks on GitHub are plain text.

## Contents

- [Why S2S Manager?](#why-s2s-manager)
- [What it manages](#what-it-manages)
- [Highlights](#highlights)
- [Safety model](#safety-model)
- [Requirements](#requirements)
- [Install](#install)
- [Update](#update)
- [Main screen](#main-screen)
- [Quick start](#quick-start)
- [State, configuration and backups](#state-configuration-and-backups)
- [Important limitations](#important-limitations)
- [Documentation](#documentation)

## Why S2S Manager?

S2S Manager started as my personal collection of notes and copy-and-paste configuration blocks. I wanted to connect several Site-to-Site locations and needed a repeatable checklist that did not omit an address, route, firewall rule or strongSwan setting. The original motivation was constructive laziness: do the careful work once instead of repeating the same error-prone steps on every server.

As I added more tunnels and VPS systems, the documentation gradually became an interactive script. Real operational needs then led to Debian peer bundles, reconnection handling, WireGuard, UFW, access checks, packet-filter diagnostics, server information and cron management. I develop features around actual use cases and test them both locally and on real Debian servers.

I have designed and developed the project iteratively in collaboration with OpenAI's ChatGPT and Codex. I define the requirements, test behavior on the target systems and decide how the tool should work; the AI assists me with analysis, implementation, automated tests and documentation. I state this openly because it is part of the project's development history, and AI assistance does not replace review or real-system testing for networking and firewall changes.

## What it manages

| Area | Main-menu entry | Capabilities |
|---|---:|---|
| IPsec Site-to-Site | 1–19 | UniFi ↔ Debian and Debian ↔ Debian tunnel lifecycle |
| Server status | 20 | Host, virtualization, CPU, memory, disk and runtime overview |
| WireGuard | 21 | Full-tunnel IPv4 server and client management |
| UFW | 22 | Safe installation, activation and incoming rule management |
| Access Check | 23 | Read-only route, firewall, NAT and local-service analysis |
| IPTABLES | 24 | Read-only filter, NAT, Docker and packet-path diagnostics |
| Cron | 25 | Inventory and management of scheduled tasks |

## Highlights

### IPsec Site-to-Site

- Route-based IKEv2/IPsec using strongSwan and `swanctl`
- Linux VTI interface and dedicated `/30` transfer network per tunnel
- Explicit VPN routes in table 220 without a catch-all default route
- UniFi Gateway and Debian/strongSwan peers
- Static IPv4, DDNS and dynamic/unknown UniFi endpoints
- Validation of address overlap, routes, endpoints and authentication IDs
- Persistent reconnection attempts for Debian peers after provider outages
- Install, uninstall, re-apply, reconnect and detailed diagnostics
- Discovery and read-only import before controlled take-over
- Take-over backups under `/root/s2s-manager/backups/`
- Portable tunnel backups and peer bundles under `/root/s2s-manager/exports/`
- Generated UniFi configuration reference

### WireGuard remote access

- New full-tunnel IPv4 server or discovery of existing configurations
- Read-only import followed by explicit migration/take-over
- Backups under `/root/s2s-manager/wireguard/backups/` and automatic rollback when migration fails
- Add, rename and remove clients while preserving active peer state
- Generated client configuration and optional QR-code display
- Change the managed `/24` VPN network while preserving keys and client host numbers
- NAT, IPv4 forwarding and table-220 integration
- Complete managed-server reset without removing packages or IPsec tunnels
- Live handshakes and RX/TX counters

### UFW firewall

- Detect, install, safely enable, disable and reload UFW
- Prepare and verify the current SSH port before activation
- Keep UFW disabled immediately after a new installation for review
- Display active numbered rules or readable stored rules while inactive
- Guided permanent TCP/UDP incoming rules
- Temporary rules with persistent systemd expiry timers
- Preview, duplicate detection and protection for SSH/VPN rules
- Clear separation from provider or cloud firewalls

### Access and packet-filter diagnostics

- Analyse traffic from a WireGuard client or custom source/interface
- Check Internet, routed-network and local TCP/UDP service access
- Inspect forwarding, route selection, UFW policy, iptables and NAT evidence
- Show INPUT, FORWARD and OUTPUT policies/rules with counters
- Show DNAT, MASQUERADE and Docker firewall chains
- Detect exact Docker DNAT mappings and explain INPUT versus FORWARD paths
- Never create, delete or flush packet-filter rules in the IPTABLES section

### Cron / scheduled tasks

- Inventory user crontabs, `/etc/crontab`, `/etc/cron.d/*` and periodic directories
- Distinguish `S2S`, `EXTERNAL` and plausible commented jobs
- Optional human-readable schedule descriptions
- Guided schedules with explained weekday values and English names
- Add, take over, edit, enable/disable, run and delete managed jobs
- Change the execution user, including guarded user-to-user migration
- Preserve unrelated jobs, variables and comments in their original source
- Back up every affected source under `/root/s2s-manager/cron/backups/` and abort after concurrent external changes
- Diagnose the cron service, users, commands, permissions and recent journal entries

## Safety model

The manager runs as root because it configures system networking and services. It therefore treats every write as an administrative operation:

- Status and inventory screens do not rewrite tunnel, firewall or cron-job configuration.
- Destructive or connectivity-sensitive operations show a preview and require confirmation.
- Existing IPsec, WireGuard and cron configurations are imported read-only first.
- IPsec take-over creates timestamped backups under `/root/s2s-manager/backups/`.
- WireGuard migration creates backups under `/root/s2s-manager/wireguard/backups/`.
- Cron changes create source backups under `/root/s2s-manager/cron/backups/`.
- WireGuard migration attempts automatic rollback after a failed start.
- Cron writes compare the selected source with its current hash to avoid overwriting parallel edits.
- UFW activation is refused without a suitable SSH safety rule.
- The Access Check and IPTABLES sections are read-only.
- Secrets are stored with restrictive permissions and are not printed in normal status views.

Always keep an independent provider console available when changing remote networking or firewall configuration.

## Requirements

- Debian 13
- Root privileges
- Bash and standard Debian system tools
- Internet/package access when dependencies must be installed
- Public IPv4 or an appropriate routed/NAT environment
- IPsec peers reachable on UDP 500 and UDP 4500
- WireGuard listen port reachable when WireGuard is used (default UDP 51820)
- SSH connectivity for direct Debian peer-bundle transfer

UFW, WireGuard, QR generation and cron support are optional until their corresponding feature is used. Provider/cloud firewalls remain outside the manager.

## Install

Log in as root or open a root shell with `sudo -i`. Choose either method below.

### Run the current GitHub version directly

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Nisbo/s2s-manager/main/s2s-manager.sh?nocache=$(date +%s)")
```

The cache-busting timestamp requests the current GitHub version each time. The script runs for this session and is not saved as a local manager file.

### Download and keep the script locally

```bash
curl -fsSL "https://raw.githubusercontent.com/Nisbo/s2s-manager/main/s2s-manager.sh?nocache=$(date +%s)" -o s2s-manager.sh
chmod +x s2s-manager.sh
./s2s-manager.sh
```

This stores `s2s-manager.sh` in the current directory so it can be started again later without downloading it. No manager package is installed and nothing is copied to `/usr/local/bin`. Feature-specific Debian packages are offered only when required and always with a confirmation.

For security-sensitive environments, inspect the repository version before executing it as root.

## Update

If the manager is normally run directly, use the same command again; it downloads the current version every time:

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Nisbo/s2s-manager/main/s2s-manager.sh?nocache=$(date +%s)")
```

If `s2s-manager.sh` was saved locally, run these commands from the directory containing it:

```bash
curl -fsSL "https://raw.githubusercontent.com/Nisbo/s2s-manager/main/s2s-manager.sh?nocache=$(date +%s)" -o s2s-manager.sh
chmod +x s2s-manager.sh
./s2s-manager.sh
```

Saved manager state and installed system configurations remain under `/root/s2s-manager/` and the listed system paths. Running a newer script does not remove them. Review the version shown in the banner after updating.

## Main screen

```text
╔══════════════════════════════════════════════════════════════╗
║                      IPsec S2S Manager                       ║
║                       Version 1.5.14                         ║
╚══════════════════════════════════════════════════════════════╝

State directory: /root/s2s-manager
Server hostname:  vps-example
Primary IPv4:     198.51.100.10

TUNNEL CONFIGURATION                         TUNNEL OPERATIONS
────────────────────────────────────────     ────────────────────────────────────────
[1] Show tunnel configuration                [7] Install tunnel on Debian
[2] Add S2S tunnel                           [8] Re-apply tunnel configuration
[3] Add remote network to tunnel             [9] Reconnect tunnel
[4] Remove remote network from tunnel        [10] Tunnel diagnostics
[5] Show UniFi configuration
[6] Rename tunnel display name

REMOVE / DELETE                              IMPORT / TAKE OVER
────────────────────────────────────────     ────────────────────────────────────────
[11] Uninstall tunnel from Debian            [13] Discover / import existing tunnels
[12] Delete tunnel completely                [14] Take over imported tunnel
                                             [15] Show Take Over backups

EXPORT / TRANSFER                            SYSTEM / VPN / UFW / IPTABLES / CRON
────────────────────────────────────────     ────────────────────────────────────────
[16] Tunnel backup / restore                 [20] Show system status
[17] Create Debian peer bundle               [21] WireGuard
[18] Transfer Debian peer bundle via SCP     [22] UFW
[19] Import Debian peer bundle               [23] Access Check (read-only)
                                             [24] IPTABLES / Packet Filter (read-only)
                                             [25] Cron / Scheduled Tasks

[E] Exit
```

## Quick start

### UniFi Gateway ↔ Debian

1. Select **[2] Add S2S tunnel** and choose **UniFi Gateway**.
2. Enter the public endpoints, unique `/30` transfer network and remote LANs.
3. Review and install the Debian side.
4. Open **[5] Show UniFi configuration** and enter the displayed values in UniFi.
5. Confirm the connection with **[10] Tunnel diagnostics**.

### Debian ↔ Debian

1. Create and install the tunnel on Server A using **[2]**.
2. Create its mirrored peer bundle with **[17]**.
3. Transfer it through **[18]**, or copy it through another protected channel.
4. Import and install it on Server B using **[19]**.
5. Verify both sides with **[10] Tunnel diagnostics**.

### WireGuard

1. Select **[21] WireGuard**.
2. Create a managed server, or inspect/import an existing server first.
3. Add a client and transfer its `.conf` file or scan its QR code.
4. Verify the handshake and traffic counters in WireGuard diagnostics.

Manager-created clients receive one `/32` address inside the server's `/24` network. This is normal for an individual WireGuard peer. Full tunnel means `AllowedIPs = 0.0.0.0/0` for IPv4 Internet access through the server; it does not automatically permit every LAN behind an IPsec peer.

### UFW

1. Select **[22] UFW** and install it if necessary.
2. Review the prepared SSH rule and add every required service/VPN rule.
3. Display the complete stored rule set.
4. Use the manager's safe activation option and keep the provider console available.

Ordinary UFW rule changes take effect immediately while UFW is active. Reload is normally unnecessary. Provider firewall rules must be configured separately.

### Cron

1. Select **[25] Cron / Scheduled Tasks** and inspect the unified inventory.
2. Add a job or explicitly take over an existing external entry.
3. Review schedule, human-readable meaning, command, user and initial status.
4. Use manual execution to test the command itself; use diagnostics/journal entries to confirm execution by cron.

Managed blocks store adjacent `S2S-JOB`, `S2S-ENABLED` and `S2S-READABLE` comments. Disabled commands use `S2S-DISABLED`. The cron expression remains authoritative; editing or toggling a job regenerates an outdated readable comment.

## State, configuration and backups

Manager state is stored below:

```text
/root/s2s-manager/
```

Important paths include:

```text
/root/s2s-manager/tunnels/
/root/s2s-manager/backups/
/root/s2s-manager/exports/
/root/s2s-manager/wireguard/
/root/s2s-manager/wireguard/backups/
/root/s2s-manager/wireguard/exports/
/root/s2s-manager/cron/backups/
/etc/swanctl/conf.d/s2s-manager-<tunnel>.conf
/usr/local/sbin/s2s-manager-vti-<tunnel>.sh
/etc/systemd/system/s2s-manager-vti-<tunnel>.service
/etc/wireguard/wg0.conf
```

Backup locations by operation:

| Data | Location |
|---|---|
| IPsec take-over safety backups | `/root/s2s-manager/backups/` |
| Portable IPsec tunnel backups | `/root/s2s-manager/exports/*.s2s-backup.tar.gz` |
| Debian peer bundles | `/root/s2s-manager/exports/*.s2s-peer` |
| WireGuard migration/network-change backups | `/root/s2s-manager/wireguard/backups/` |
| Generated WireGuard client files | `/root/s2s-manager/wireguard/exports/` |
| Cron source backups | `/root/s2s-manager/cron/backups/` |

Safety backups are retained until they are removed manually. Peer bundles, tunnel backups, WireGuard client exports and QR codes may contain PSKs or private keys. Treat them like passwords and never publish them.

## Important limitations

- Every IPsec tunnel needs a unique, non-overlapping `/30` transfer network.
- Overlapping remote routes are rejected because they make routing ambiguous.
- A classic VTI has one concrete remote endpoint; DDNS names resolving to multiple IPv4 addresses are rejected.
- Only one wildcard VTI endpoint can use the same Debian public IPv4.
- A server-side Access Check provides configuration evidence, not an end-to-end packet test from the remote client.
- Arbitrary ordered nftables/iptables rules cannot always be reduced to a guaranteed verdict.
- Opening a local UFW port does not open the corresponding provider/cloud firewall.
- The guest OS usually cannot determine whether KVM/QEMU is managed by Proxmox, OpenStack or another host platform.

## Documentation

Use the [S2S Manager Wiki](https://github.com/Nisbo/s2s-manager/wiki) as the navigable, detailed documentation. The repository's [MANUAL.md](MANUAL.md) remains available as a single-file/offline reference.

## License

No license has been published for this repository. Unless a license is added, normal copyright restrictions apply.
