# Per-session L2TP/IPsec(PSK) VPN — test implementation

Goal: route **only a single RLogin session** through an L2TP/IPsec (pre-shared
key) VPN, without turning the whole machine into a VPN client and without
leaving any VPN configuration behind in Windows.

This branch (`feat/l2tp-ipsec-per-session`) is a **test implementation / PoC**.
It compiles against the upstream RLogin tree but has **not** been built/run yet
(no Windows + MSVC/MFC in the authoring environment). Build & verify on the
Windows runner.

## How it works

```
On connect (CRLoginDoc::SocketOpen):
  1. CRasVpn::Dial()
       - create an EPHEMERAL RAS phonebook entry "RLoginTmp_<pid>_<n>"
         (RASET_Vpn, VpnStrategy = VS_L2tpOnly)
       - split tunnel: RASEO_RemoteDefaultGateway is intentionally NOT set,
         so the VPN never becomes the default route
       - store the PSK (RasSetCredentials / RASCM_PreSharedKey)
       - RasDial (blocking), confirm RASCS_Connected
       - map the tunnel's PPP IP -> adapter interface index (IfIndex/Ipv6IfIndex)
  2. stash if4/if6 on the CExtSocket
  3. when the socket is created (CFifoSocket::SocketLoop), bind it to the VPN
     adapter with setsockopt(IP_UNICAST_IF / IPV6_UNICAST_IF)
       => only THIS socket egresses through the tunnel; everything else on the
          machine keeps its normal route
On close (CRLoginDoc::SocketClose):
  4. CRasVpn::Release()/HangUp() -> RasHangUp + RasDeleteEntry (no trace left)
On app start (CRLoginApp::InitInstance):
  5. CRasVpn::CleanupOrphans() -> delete stray "RLoginTmp_*" entries from a
     previous crashed run
```

The key mechanism is `IP_UNICAST_IF`: it forces a specific socket onto a chosen
interface, overriding the routing table, **without admin rights and without
changing any system route**. That is what makes the VPN "per application /
per session" instead of system-wide. (IPv4 wants the index in *network* byte
order, IPv6 in *host* byte order — see `Fifo.cpp`.)

## Files changed

| File | Change |
|------|--------|
| `RasVpn.h` / `RasVpn.cpp` | **new** — `CRasVpn`: ephemeral RAS L2TP/IPsec dialer, ifindex resolver, orphan cleanup. Links `rasapi32.lib` + `iphlpapi.lib` via `#pragma comment`. |
| `Data.h` | `CServerEntry`: `m_VpnEnable / m_VpnServer / m_VpnUser / m_VpnPass / m_VpnPsk` |
| `Data.cpp` | `Init` / `operator=` / `GetArray` / `SetArray` — VPN fields appended at serialization indexes 28–32 (back-compatible; old sessions just lack them). Pass + PSK are encrypted like other passwords and cleared if the password-integrity check fails. |
| `ExtSocket.h` / `ExtSocket.cpp` | `m_VpnIfIndex4/6` on `CExtSocket`; propagated to `CFifoSocket` in `Open()` |
| `Fifo.h` / `Fifo.cpp` | `m_VpnIfIndex4/6` on `CFifoSocket`; `IP_UNICAST_IF` injection right after `::socket()` in the connect loop |
| `RLoginDoc.h` / `RLoginDoc.cpp` | `m_pRasVpn`; dial before proxy/open, hangup in `SocketClose` |
| `RLogin.cpp` | `CRasVpn::CleanupOrphans()` at startup |
| `RLogin.vcxproj` / `.filters` | add `RasVpn.cpp/.h` |

## NOT done yet (follow-ups)

- **Settings UI.** There is no dialog to edit the VPN fields. The storage and
  the whole runtime path are wired, but to *set* `m_VpnEnable` etc. a property
  page (e.g. next to the existing Proxy page) plus `.rc`/`resource.h` entries
  are needed — best added in Visual Studio. Until then the fields can only be
  populated programmatically / via an imported session.
- **Build verification** on Windows (MSVC + MFC + Windows SDK).

## Caveats to verify on Windows

1. **PSK may require administrator.** `RasSetCredentials(RASCM_PreSharedKey)`
   writes to the LSA secret store, which historically needs elevation. If it
   fails with access-denied, options: (a) run RLogin elevated, or (b) switch to
   a persistent entry whose PSK is set once by an elevated helper and reuse it
   (drops the "ephemeral" property). The dial error message already hints at
   this.
2. **NAT-T.** If the client is behind NAT, Windows refuses L2TP/IPsec unless
   `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent\AssumeUDPEncapsulationContextOnSendRule = 2`
   (DWORD) is set **and the machine is rebooted**. One-time, admin, outside
   RLogin's control.
3. **`RASENTRY.szDeviceName`** is currently a generic `"WAN Miniport (L2TP)"`.
   `VS_L2tpOnly` forces the protocol regardless, but if the entry is rejected,
   enumerate VPN devices with `RasEnumDevices` (type `RASDT_Vpn`) and use the
   real name.
4. **Routing for the target.** `IP_UNICAST_IF` forces the egress interface, but
   the destination must be reachable *via that interface*. For hosts inside the
   VPN's pushed subnets (the normal case) the route exists and it just works.
   To force an arbitrary public destination through the VPN you'd additionally
   need a host route (`CreateIpForwardEntry`, which needs admin) — not required
   for the intended use.
5. **DNS.** Hostname resolution still uses the default path. If in-VPN DNS is
   required, connect by IP or resolve through the tunnel explicitly.

## Quick manual test (before the UI exists)

1. Build on Windows.
2. Populate a session's VPN fields programmatically (or temporarily hardcode in
   `SocketOpen` for a smoke test): server, user, pass, psk, enable = TRUE.
3. Connect the session; in another shell confirm the SSH/target traffic goes
   over the PPP adapter (e.g. `Get-NetTCPConnection`, or a capture on the
   physical NIC shows only ESP/UDP-4500 to the VPN server), while other apps
   keep using the normal route.
4. Close the session; confirm the `RLoginTmp_*` entry is gone (`rasphone -a`
   list / `RasEnumEntries`).
