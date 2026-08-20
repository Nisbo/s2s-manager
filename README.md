# IPsec S2S Manager

Interactive Bash manager for **route-based IKEv2/IPsec Site-to-Site tunnels on Debian 13** using **strongSwan/swanctl**, Linux **VTI** interfaces and optional **WireGuard full-tunnel remote access**.

It is designed for three common scenarios:

- **UniFi Gateway ↔ Debian** IPsec S2S
- **Debian / strongSwan ↔ Debian / strongSwan** IPsec S2S
- **Phone / tablet / computer ↔ Debian** WireGuard full-tunnel VPN

The manager guides you through setup, validates conflicts, creates and maintains the required configuration, and provides diagnostics, import/take-over, backup and transfer tools.

> All addresses and names in the examples are fictional documentation data. The real program uses terminal colors; the simulated screens below are plain text so they render reliably on GitHub.

## Features

### IPsec Site-to-Site

- Route-based **IKEv2/IPsec** with **strongSwan / swanctl**
- Linux **VTI** interfaces and a separate `/30` transfer network per tunnel
- Routing through **table 220**
- UniFi Gateway and Debian/strongSwan peers
- Static IPv4, hostname/DDNS and dynamic/unknown UniFi endpoints
- Automatic VTI interface and mark/key allocation
- Network overlap, route, endpoint and Authentication-ID conflict validation
- Remote-network management
- Generated UniFi configuration reference
- Install, uninstall, re-apply and reconnect operations
- IKE/CHILD_SA, VTI, routing and traffic diagnostics
- Tunnel backup/restore
- Discovery and read-only import of existing strongSwan/VTI tunnels
- Controlled take-over with timestamped backups
- Debian peer bundles containing the mirrored settings and PSK
- Direct peer-bundle transfer via SCP
- Optional UFW rules for UDP 500/4500

### WireGuard remote access

- Create a new **full-tunnel IPv4 WireGuard server**
- Detect existing `/etc/wireguard/*.conf` installations
- Read-only import of existing servers and peers
- Controlled migration/take-over with automatic backup and rollback on failed start
- Existing server private key, peer public keys, PSKs and client IPs are preserved where available
- Add and remove managed clients without restarting `wg0`
- Live peer updates preserve existing client sessions, handshake timestamps and traffic counters
- Rename client display names without changing keys or VPN IPs
- Generate complete client `.conf` files for manager-created clients
- Display QR codes; `qrencode` can be installed on demand
- Show SCP/SFTP transfer instructions for macOS, Linux and Windows PowerShell
- Full-tunnel Internet access (`AllowedIPs = 0.0.0.0/0`)
- NAT/forwarding setup and IPv4 forwarding
- Integration with IPsec policy routing: the whole WireGuard VPN network is added to table 220 when required
- WireGuard status, live handshakes and RX/TX counters
- Optional UFW rule for the configured WireGuard UDP port

### UFW firewall management

- Dedicated **[22] UFW** main-menu entry
- Detect whether UFW is installed and whether it is active
- Offer safe package installation when UFW is missing
- Detect the current SSH server port and prepare its allow rule first
- Keep UFW disabled after installation so existing traffic is not unexpectedly blocked
- Show status/default policies, all numbered rules and stored rules while UFW is inactive
- Add permanent incoming TCP/UDP allow rules with a guided preview
- Add temporary allow rules with a persistent systemd expiry timer (15 minutes through 7 days)
- Mark displayed rules as `[PERMANENT]` or `[TEMP until ...]`
- Delete numbered active rules with preview, typed confirmation and SSH/VPN protection
- Reject duplicate rules so an existing permanent rule cannot accidentally become temporary
- Keep provider/cloud firewall management explicitly separate

## Requirements

- Debian **13**
- root privileges
- Internet/package access for initial package installation
- Public IPv4 or a suitable routed/NAT environment
- IPsec: UDP **500** and **4500** reachable between peers
- WireGuard: configured UDP listen port reachable (default **51820**)
- Debian-to-Debian bundle transfer: SSH access between servers

Provider/cloud firewalls are separate from UFW and must be configured independently.

## Installation

Save the stable script as `s2s-manager.sh` and run:

```bash
chmod +x s2s-manager.sh
sudo ./s2s-manager.sh
```

When already logged in as root:

```bash
./s2s-manager.sh
```

Manager state is stored under:

```text
/root/s2s-manager/
```

Important managed paths include:

```text
/etc/swanctl/conf.d/s2s-manager-<tunnel>.conf
/usr/local/sbin/s2s-manager-vti-<tunnel>.sh
/etc/systemd/system/s2s-manager-vti-<tunnel>.service
/etc/wireguard/wg0.conf
/root/s2s-manager/wireguard/
```

## Main screen

```text
╔══════════════════════════════════════════════════════════════╗
║                      IPsec S2S Manager                       ║
║                       Version 1.3.4                          ║
╚══════════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────────
  CONFIGURED TUNNELS
──────────────────────────────────────────────────────────────
#    Name                    Interface   Tunnel Network       Management  Connection
1    Office-UniFi            ipsec0      10.200.202.0/30      MANAGED     CONNECTED
2    VPS-East - VPS-West     ipsec1      10.200.210.0/30      MANAGED     CONNECTED

  TUNNEL CONFIGURATION                         TUNNEL OPERATIONS
  ─────────────────────────────────────────    ────────────────────────────────────────
  [1] Show tunnel configuration                [7] Install tunnel on Debian
  [2] Add S2S tunnel                           [8] Re-apply tunnel configuration
  [3] Add remote network to tunnel             [9] Reconnect tunnel
  [4] Remove remote network from tunnel        [10] Tunnel diagnostics
  [5] Show UniFi configuration
  [6] Rename tunnel display name

  REMOVE / DELETE                              IMPORT / TAKE OVER
  ─────────────────────────────────────────    ────────────────────────────────────────
  [11] Uninstall tunnel from Debian            [13] Discover / import existing tunnels
  [12] Delete tunnel completely                [14] Take over imported tunnel
                                                [15] Show Take Over backups

  EXPORT / TRANSFER                            SYSTEM / VPN / FIREWALL
  ─────────────────────────────────────────    ────────────────────────────────────────
  [16] Tunnel backup / restore                 [20] Show system status
  [17] Create Debian peer bundle               [21] WireGuard
  [18] Transfer Debian peer bundle via SCP
  [19] Import Debian peer bundle               [22] UFW

  [E] Exit
```

## Quick start: UniFi Gateway ↔ Debian

Example values:

| Item | Example |
|---|---|
| Debian public IPv4 | `198.51.100.10` |
| UniFi public IPv4 | `203.0.113.20` |
| Transfer network | `10.200.202.0/30` |
| Debian VTI | `10.200.202.1` |
| UniFi VTI | `10.200.202.2` |
| UniFi LAN | `192.168.10.0/24` |
| Authentication ID | `office-unifi` |

Use **[2] Add S2S tunnel**, choose **UniFi Gateway**, complete the wizard, install the tunnel, then use **[5] Show UniFi configuration** to obtain the matching values for UniFi. Verify it with **[10] Tunnel diagnostics**.

## Quick start: Debian ↔ Debian

Create the tunnel on Server A with **[2] Add S2S tunnel** and choose **Debian / strongSwan**. After saving/installing it, use **[17] Create Debian peer bundle** and **[18] Transfer Debian peer bundle via SCP**. On Server B use **[19] Import Debian peer bundle**, review the validation preview and install it. Finally use **[9] Reconnect tunnel** if necessary and **[10] Tunnel diagnostics** on both sides.

## Quick start: WireGuard remote access

Choose **[21] WireGuard**. On a new server, create a manager-owned WireGuard server. If `/etc/wireguard` already contains a server, first import it read-only, verify status, then migrate/take it over if desired.

For a managed server, open **WireGuard clients → Add client**. The generated client uses a `/32` address such as `10.250.0.2/32`; this is correct for an individual WireGuard peer even though the server owns the complete `/24` VPN network. The client receives `AllowedIPs = 0.0.0.0/0`, so IPv4 Internet traffic is sent through the VPN server.

The client can then be imported using its generated `.conf` file or the QR-code view. Existing imported peers can remain connected and be removed/renamed in manager state after migration, but their original client private keys are not present on the server, so their complete client configuration and QR code cannot be reconstructed.

## Quick start: UFW firewall management

Choose **[22] UFW**. If UFW is installed, use **Show all firewall rules** to display its status/default policies, each rule once in a numbered list and—when inactive—the rules stored for later activation.

If UFW is missing, the manager can install it and prepare an allow rule for the detected SSH administration port. This first implementation deliberately leaves UFW disabled after installation. Review all required HTTP, HTTPS, IPsec, WireGuard and custom-service ports before enabling it manually or extending its rule set.

Permanent and temporary incoming ALLOW rules can be added for TCP or UDP. The source may be `any`, one plain IPv4 address or one IPv4 CIDR network. URL syntax such as `https://`, hostnames and values containing `:port` are not accepted in the source field.

Temporary rules use an on-disk systemd timer and remain clearly marked with their expiry time. The timer survives a reboot and removes the matching UFW rule at expiry. Rules can be deleted by number while UFW is active. The manager refuses to delete the detected current SSH rule and shows an additional warning for WireGuard, IKE, NAT-T and ESP rules.

## Safety model

The manager separates saved state from installed system configuration. Destructive operations show previews/confirmations, sensitive PSKs and WireGuard client keys are stored with restrictive permissions, existing tunnel/server take-over creates backups, and external bundle/backup data is parsed rather than executed as shell code.

WireGuard migration automatically restores the configuration backed up immediately before migration if the newly generated managed configuration cannot start.

## Documentation

See **[MANUAL.md](MANUAL.md)** for the complete menu reference, UniFi/Debian walkthroughs, WireGuard setup/import/migration/client workflows and troubleshooting.

## Important notes

- Every IPsec tunnel needs its own non-overlapping `/30` transfer network.
- Do not create ambiguous overlapping remote routes.
- A classic VTI has one concrete remote endpoint; DDNS names resolving to multiple IPv4 addresses are rejected.
- Dynamic/unknown UniFi mode uses a wildcard VTI endpoint; only one wildcard VTI can use the same Debian public IPv4.
- WireGuard manager-created clients use `/32` addresses by design.
- Full-tunnel WireGuard currently means Internet access through the Debian server. It does **not** automatically grant access to all networks behind S2S peers.
- Opening ports in UFW does not configure a provider/cloud firewall.
- Peer bundles, backups and WireGuard client exports can contain secrets. Treat them like passwords.

## License

Add the license you want to use for the project here before publishing the repository.
