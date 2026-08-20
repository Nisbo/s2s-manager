# IPsec S2S Manager — Manual

This manual describes **IPsec S2S Manager 1.3.3**.

All IP addresses, hostnames, client names and networks below are fictional documentation data.

---

# 1. Concept

The manager combines two related VPN jobs on Debian 13:

1. **Route-based IKEv2/IPsec Site-to-Site** using strongSwan/swanctl and Linux VTI interfaces.
2. **WireGuard full-tunnel remote access** for phones, tablets and computers.

An IPsec S2S tunnel receives its own `/30` point-to-point transfer network. Remote LAN/VLAN routes are placed through its VTI. The manager uses routing table **220** for the S2S return-routing design.

```text
UniFi / Debian peer                         Debian server
203.0.113.20                               198.51.100.10
      │                                          │
      └──────────── IKEv2 / IPsec ───────────────┘
                  10.200.202.0/30
             .2  ◄──────────────►  .1
                  VTI interface
```

WireGuard uses a separate VPN network, for example `10.250.0.0/24`. The server owns `10.250.0.1/24`; individual clients receive addresses such as `10.250.0.2/32`. A managed client uses `AllowedIPs = 0.0.0.0/0`, making it an IPv4 full tunnel through the Debian server.

---

# 2. State and system files

Manager state:

```text
/root/s2s-manager/
```

IPsec system files use names such as:

```text
/etc/swanctl/conf.d/s2s-manager-office-unifi.conf
/usr/local/sbin/s2s-manager-vti-office-unifi.sh
/etc/systemd/system/s2s-manager-vti-office-unifi.service
```

WireGuard uses:

```text
/etc/wireguard/wg0.conf
/root/s2s-manager/wireguard/server.conf
/root/s2s-manager/wireguard/server.key
/root/s2s-manager/wireguard/clients/
/root/s2s-manager/wireguard/exports/
/root/s2s-manager/wireguard/backups/
```

Sensitive state is stored with restrictive permissions.

IPsec management states include **DEFINED**, **MANAGED**, **IMPORTED** and **PARTIAL/BROKEN**. WireGuard uses **MANAGED** and **IMPORTED**; imported WireGuard servers are read-only until migration/take-over.

---

# 3. Pre-flight setup

On first use the manager checks Debian 13, root privileges, required strongSwan packages, `iproute2`, OpenSSL and route-based strongSwan preparation. It can install/repair missing prerequisites.

IPsec requires UDP **500** and **4500**. WireGuard requires its configured UDP listen port, default **51820**. UFW support is optional. A provider/cloud firewall remains separate and must allow the same required traffic.

---

# 4. Main menu

```text
  TUNNEL CONFIGURATION                         TUNNEL OPERATIONS
  [1] Show tunnel configuration                [7] Install tunnel on Debian
  [2] Add S2S tunnel                           [8] Re-apply tunnel configuration
  [3] Add remote network to tunnel             [9] Reconnect tunnel
  [4] Remove remote network from tunnel        [10] Tunnel diagnostics
  [5] Show UniFi configuration
  [6] Rename tunnel display name

  REMOVE / DELETE                              IMPORT / TAKE OVER
  [11] Uninstall tunnel from Debian            [13] Discover / import existing tunnels
  [12] Delete tunnel completely                [14] Take over imported tunnel
                                                [15] Show Take Over backups

  EXPORT / TRANSFER                            SYSTEM / VPN / FIREWALL
  [16] Tunnel backup / restore                 [20] Show system status
  [17] Create Debian peer bundle               [21] WireGuard
  [18] Transfer Debian peer bundle via SCP
  [19] Import Debian peer bundle               [22] UFW
```

---

# 5. IPsec menu reference

## [1] Show tunnel configuration
Displays the saved definition, peer type, management/connection state, public endpoint, Authentication ID, VTI interface/key, `/30` transfer network and configured remote networks. Read-only.

## [2] Add S2S tunnel
Starts the creation wizard: display name, peer type, peer endpoint, Debian public IP, transfer network, Authentication ID, remote networks and PSK. The manager validates conflicts before saving/installing.

## [3] Add remote network
Adds a CIDR reachable through the remote side. The manager checks overlaps with transfer networks, other manager routes and live Debian routes.

## [4] Remove remote network
Removes a route from the saved definition without deleting the tunnel.

## [5] Show UniFi configuration
For UniFi peers, prints the values to enter in UniFi: route-based tunnel IP, IKEv2/ESP proposals, Authentication IDs and PSK on explicit request.

## [6] Rename tunnel display name
Changes only the human-readable name. Internal filenames, service names and technical tunnel identity remain unchanged.

## [7] Install tunnel on Debian
Creates the manager-owned strongSwan configuration, VTI script/service and table-220 routes from a saved DEFINED tunnel.

## [8] Re-apply tunnel configuration
Regenerates manager-owned files from saved state. It is a configuration operation, not the same as reconnecting an established SA.

## [9] Reconnect tunnel
Terminates and re-establishes the current IKE/CHILD SAs. Traffic is briefly interrupted.

## [10] Tunnel diagnostics
Shows service/interface state, table-220 routes, IKE/CHILD_SA state, NAT-T information and traffic counters. Optional tests include remote-VTI ping, connection uptime analysis and recent strongSwan logs.

## [11] Uninstall tunnel from Debian
Removes installed manager-owned system configuration but keeps the definition, routes and PSK for later reinstall.

## [12] Delete tunnel completely
Removes the tunnel and its manager state. Back up first if it may be needed later.

## [13] Discover / import existing tunnels
Scans existing strongSwan/VTI configuration and imports a compatible tunnel read-only. Existing files remain authoritative.

## [14] Take over imported tunnel
Creates a timestamped backup, validates the proposed manager configuration and converts the imported tunnel to manager ownership.

## [15] Show Take Over backups
Read-only view of backups created during take-over.

## [16] Tunnel backup / restore
Creates/restores portable manager tunnel backups. Restored tunnels return as DEFINED and are not installed automatically. Existing internal names are not silently overwritten.

## [17] Create Debian peer bundle
Creates the mirrored configuration for the second Debian/strongSwan server. The bundle includes the shared PSK and is sensitive.

## [18] Transfer Debian peer bundle via SCP
Transfers a peer bundle directly to the second server, normally into `/root/s2s-manager-import/`.

## [19] Import Debian peer bundle
Validates the bundle and local conflicts, shows a preview, then creates the mirrored local tunnel after confirmation.

## [20] Show system status
Shows host-level prerequisite and IPsec/VTI status.

---

# 6. Complete walkthrough — UniFi Gateway ↔ Debian

Example topology:

```text
UniFi Gateway                             Debian VPS
203.0.113.20                            198.51.100.10
      │                                       │
      └──────── IKEv2 / IPsec ────────────────┘
            10.200.202.2/30       10.200.202.1/30
                  │
          192.168.10.0/24
```

1. Choose **[2] Add S2S tunnel**.
2. Display name: `Office-UniFi`.
3. Peer type: **UniFi Gateway**.
4. Select Dynamic/unknown, Static IPv4 or Hostname/DDNS. For this example use `203.0.113.20`.
5. Confirm Debian public IP `198.51.100.10`.
6. Accept/select `10.200.202.0/30`; Debian becomes `.1`, UniFi `.2`.
7. Set Authentication ID, for example `office-unifi`.
8. Add remote network `192.168.10.0/24` and any additional UniFi LAN/VLAN CIDRs.
9. Generate a secure PSK or enter your own.
10. Save and install the tunnel.
11. Choose **[5] Show UniFi configuration**.

Simulated UniFi reference:

```text
VPN Type:                       IPsec
Remote IP / Hostname:           198.51.100.10
VPN Method:                     Route Based
Tunnel IP:                      Enabled
IPv4 Address:                   10.200.202.2
Netmask:                        30
Key Exchange Version:           IKEv2
IKE:                            AES-256 / SHA256 / DH14 / 28800
ESP:                            AES-256 / SHA256 / DH14 / 3600
Perfect Forward Secrecy:        Enabled
Local Authentication ID:        office-unifi
Remote Authentication ID:       198.51.100.10
```

Copy the same PSK to UniFi. The exact UniFi UI labels may change between Network versions; the manager's generated values are the tunnel reference.

Finally choose **[10] Tunnel diagnostics**. A healthy tunnel should show strongSwan active, VTI present, IKE established and CHILD_SA installed.

---

# 7. Complete walkthrough — Debian ↔ Debian

Example:

```text
Debian A                                      Debian B
198.51.100.10                               203.0.113.50
      │                                            │
      └──────────── IKEv2 / IPsec ─────────────────┘
 10.200.210.1  ◄──── 10.200.210.0/30 ────►  10.200.210.2
```

On **Debian A**:

1. **[2] Add S2S tunnel** → **Debian / strongSwan**.
2. Enter Debian B's public IPv4/hostname.
3. Confirm Debian A's public IP.
4. Select a free `/30`, for example `10.200.210.0/30`.
5. Add networks behind B that A must reach.
6. Generate the PSK and install.
7. **[17] Create Debian peer bundle**.
8. **[18] Transfer Debian peer bundle via SCP** to Debian B.

On **Debian B**:

9. Run the manager.
10. **[19] Import Debian peer bundle**.
11. Review conflict validation and preview.
12. Confirm import/install.
13. Add any networks behind A that B must reach; routed networks are directional.
14. Use **[9] Reconnect tunnel** if required.
15. Use **[10] Tunnel diagnostics** on both sides and test the remote VTI IP.

---

# 8. WireGuard

Choose **[21] WireGuard** from the main menu.

The WireGuard feature provides IPv4 full-tunnel remote access. It is intentionally separate from IPsec S2S. A WireGuard client gets Internet access through the Debian server, but automatic access to every remote S2S LAN is not currently configured by this feature.

## 8.1 New server

Choose WireGuard server setup and create a new manager-owned server. Typical defaults are:

```text
Interface:                   wg0
VPN network:                 10.250.0.0/24
Server VPN IP:               10.250.0.1/24
Listen port:                 UDP 51820
Client DNS:                  1.1.1.1
```

The manager detects the Internet egress interface, enables IPv4 forwarding, writes NAT/FORWARD rules and can manage the UFW UDP rule. If S2S policy routing via table 220 is active, the manager adds the **whole WireGuard VPN network** to table 220:

```text
10.250.0.0/24 dev wg0 table 220
```

This is one network route, not one route per WireGuard client.

## 8.2 Detect/import an existing WireGuard server

If `/etc/wireguard` already contains a compatible configuration, choose discovery/import.

Example:

```text
──────────────────────────────────────────────────────────────
  DISCOVER EXISTING WIREGUARD SERVER
──────────────────────────────────────────────────────────────

  [1] wg0            10.7.0.1/24  UDP 51820
```

**Import read-only** records the server and peers in manager state without changing the live interface, firewall or configuration. Existing peers appear as `IMPORTED`.

The server-side configuration contains peer public keys and may contain PSKs, but it does **not** contain each client's private key. Therefore an imported peer's complete client `.conf` and QR code cannot be reconstructed.

## 8.3 Migrate / take over an imported server

Migration converts a read-only imported server into manager ownership. The manager:

- creates a timestamped backup;
- keeps the existing server private key;
- keeps peer public keys, available PSKs and `/32` client IPs;
- enables IPv4 forwarding;
- creates manager-owned full-tunnel NAT/FORWARD rules;
- adds the WireGuard network to table 220 when required;
- manages the configured UFW UDP rule when applicable;
- restarts the WireGuard service for the migration itself.

Custom old `PostUp`/`PostDown` commands are deliberately not copied automatically.

If the new managed configuration fails to start, the manager automatically restores the configuration backed up immediately before migration and restarts the old setup.

## 8.4 WireGuard server menu

For a managed server the server menu can change endpoint/port/client DNS and explicitly restart/re-apply the complete WireGuard server configuration.

A full server re-apply **does restart `wg0`**. This is appropriate for server-level settings and can reset runtime handshake/counter information until clients communicate again.

## 8.5 WireGuard clients

Example client screen:

```text
──────────────────────────────────────────────────────────────
  WIREGUARD CLIENTS
──────────────────────────────────────────────────────────────

#    Name                     VPN IP          Type         Handshake
──   ──────────────────────   ──────────────  ──────────   ────────────────
1    UDM Pro                  10.7.0.2        IMPORTED     2s ago
2    iPhone                   10.7.0.3        MANAGED      8s ago
3    MacBook                  10.7.0.4        MANAGED      1m 12s ago

  [1] Add client
  [2] Show client configuration
  [3] Show client QR code
  [4] Rename client display name
  [5] Export / transfer client configuration
  [6] Remove client
  [B] Back
```

### Add client

Creates a new key pair and PSK, assigns the next free client IP and generates a client export. Example:

```text
Client:                      iPhone
VPN IP:                      10.7.0.3
Config file:                 /root/s2s-manager/wireguard/exports/iphone.conf
```

A generated client contains:

```text
[Interface]
PrivateKey = <client-private-key>
Address = 10.7.0.3/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
PresharedKey = <psk>
Endpoint = vpn.example.net:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`/32` on the client is intentional: that peer owns one VPN address. It does not mean the server VPN network is limited to one client.

**Version 1.3.0:** adding/removing a client updates WireGuard peers live with `wg syncconf` instead of restarting `wg0`. Existing sessions, handshake timestamps and traffic counters therefore remain intact.

### Show client configuration
Shows the complete configuration for manager-created clients. It contains private key material. Imported peers cannot show a complete config because their client private key is unknown to the server.

### Show client QR code
Displays the manager-created client configuration as a terminal QR code. If `qrencode` is missing, the manager offers to install it. The QR code contains the client private key and must be treated as sensitive.

### Rename client display name
Changes only the manager display name. Keys, IP and live peer identity do not change.

### Export / transfer client configuration
Shows the export path and ready-to-use transfer instructions for:

- macOS/Linux `scp`;
- Windows PowerShell `scp` with OpenSSH Client;
- SFTP/WinSCP fallback details.

Run the displayed `scp` command **on the client computer**, not on the VPN server.

### Remove client
Deletes the manager client state/export and removes the peer live from WireGuard. In 1.3.0 this does not require a `wg0` restart.

## 8.6 Status / diagnostics

The WireGuard diagnostics screen shows management state, service, interface, VPN network, server VPN IP, port, endpoint, DNS, egress interface, public key and IPv4 forwarding state.

It also checks table 220. When policy routing is active, a healthy result is similar to:

```text
[✓] Routing table 220: 10.7.0.0/24 -> wg0
```

Client rows show the latest live handshake plus RX/TX counters. `Never` means WireGuard currently has no runtime handshake timestamp for that peer.

---

# 9. UFW and provider firewalls

UFW is optional. The manager can add its own required rules, but it never makes a provider firewall change.

Required inbound ports:

```text
IPsec:       UDP 500, UDP 4500
WireGuard:   configured UDP port, normally 51820
SSH:         keep your administration port reachable before enabling UFW
```

Choose **[22] UFW** from the main menu for the dedicated firewall view.

When UFW is installed, the menu reports whether it is active and provides **Show all firewall rules**. This view displays:

- UFW status, logging and default policies without repeating the rule table;
- all rules once in a numbered list;
- the stored `ufw show added` rules when UFW is inactive.

When UFW is not installed, the menu offers a guarded installation path. It detects the current SSH server port from the active SSH connection or the `sshd` configuration, installs the package and prepares an SSH allow rule with the comment `S2S Manager SSH safety`.

The dedicated installation path intentionally leaves UFW **disabled**. Installing a firewall and immediately enabling a default-deny policy could block HTTP, HTTPS, IPsec, WireGuard or another service that has not been reviewed yet. After installation, inspect the complete stored rule set before enabling UFW.

The existing IPsec and WireGuard setup paths continue to manage their own required UFW rules when requested. When UFW is not used, configure the same ports in the external/provider firewall.

---

# 10. Backup and restore

IPsec tunnel backups are available through **[16]**. WireGuard migration backups are stored separately under:

```text
/root/s2s-manager/wireguard/backups/
```

Backups and exports can contain PSKs/private keys. Protect them accordingly.

---

# 11. Troubleshooting

## IPsec tunnel is DEFINED but not connected
A definition is not installed. Use **[7] Install tunnel on Debian**.

## VTI exists but IKE/CHILD_SA is missing
Use **[10] Tunnel diagnostics**, inspect recent strongSwan logs and reconnect after both peers are configured.

## DDNS resolves to multiple A records
A classic VTI needs one concrete remote IPv4 endpoint, so the manager rejects this.

## WireGuard connects but Internet does not work
Check diagnostics for IPv4 forwarding, NAT/FORWARD rules and table 220. If table 220 policy routing is active, the complete WireGuard network must route to `wg0` there.

Useful check:

```bash
ip route show table 220
ip route get <wireguard-client-ip>
```

The client IP should resolve to `dev wg0` when table 220 is active.

## WireGuard client shows `/32`
Correct. Each client owns one address, e.g. `10.7.0.3/32`. The server still owns the overall VPN subnet, e.g. `10.7.0.0/24`.

## Imported peer has no QR code/config
Expected. A WireGuard server does not know an existing client's private key. Only manager-created clients have enough key material for a complete export/QR code.

## Handshake says `Never` after a full server restart
Runtime handshake information is held by WireGuard. After a full `wg0` restart it is empty until that client communicates again. Normal add/remove client operations in version 1.3.0 use live peer synchronization and no longer restart the interface.

## WireGuard migration fails
The manager creates a backup immediately before migration and automatically attempts rollback if the managed configuration fails to start. The backup path is printed on screen.

---

# 12. Security notes

- Never publish PSKs, WireGuard private keys, client exports or QR codes.
- WireGuard **public keys** are not secret; private keys and PSKs are.
- Treat `.s2s-peer`, tunnel backups and WireGuard `.conf` exports as sensitive.
- Review provider firewall rules separately from UFW.
- Imported external configuration is initially read-only specifically to avoid silently taking ownership of a working VPN.
