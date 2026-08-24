# NetGhost

> Scanning, diagnostics and conflict-detection tool for Windows corporate networks.
> Built entirely in PowerShell with a native WPF interface. No external dependencies, no installation.

---

## Index

- [What is NetGhost?](#what-is-netghost)
- [Motivation](#motivation)
- [Main features](#main-features)
- [Requirements](#requirements)
- [Installation and usage](#installation-and-usage)
- [Detailed functional description](#detailed-functional-description)
  - [Network autodetection](#network-autodetection)
  - [Network scan](#network-scan)
  - [Conflict analysis](#conflict-analysis)
  - [ARP tools](#arp-tools)
  - [Activity log](#activity-log)
- [Technical architecture](#technical-architecture)
- [Code structure](#code-structure)
- [Known limitations](#known-limitations)
- [Tests](#tests)
- [License](#license)

---

## What is NetGhost?

NetGhost is a network administration tool written in PowerShell that lets technicians and system engineers take a quick inventory of active machines on a local subnet, detect IP addressing conflicts and diagnose access problems, all from a WPF interface with no additional software to install.

The name refers to that class of network problems you cannot see at first glance: ghost machines that answer ping but never show up in ARP, duplicate IPs causing intermittent failures, or repeated NetBIOS names creating confusion in domain environments. NetGhost brings them to light.

---

## Motivation

In mid-sized and large corporate environments it is common to run into situations conventional network monitors do not catch well: a printer with a static IP colliding with DHCP, a machine that was decommissioned but whose ARP entry is still alive, or two computers sharing a NetBIOS name after a poorly documented migration.

Professional network management suites (SolarWinds, PRTG, Lansweeper) cover these cases but demand infrastructure, licenses and deployment time. In many scenarios what you need is something that works right now, on the machine in front of you, without installing anything.

NetGhost was born from that concrete need: a script any technician can run straight from PowerShell, with a usable interface (not just console text) and actionable information in under a minute.

---

## Main features

**Active network scan**
- Sequential ping over the configured IP range, fixed 500 ms timeout.
- NetBIOS name resolution via `nbtstat` with reverse-DNS fallback.
- ARP table readout to obtain MAC addresses without elevation.
- Vendor identification by OUI prefix (embedded table, no external calls).
- SMB (445) and RDP (3389) TCP port checks to assess accessibility.
- Automatic classification of every host: `OK`, `WARN` or `SIN_ARP`.

**Network autodetection**
- Identifies the active adapter with a gateway defined at startup.
- Filters virtual adapters: Hyper-V, VMware, VirtualBox, TAP, Tunnel, WAN Miniport, Bluetooth and others.
- Prioritization by route metric — the same criterion Windows uses to pick the preferred interface.
- Auto-preloads network address, CIDR prefix and usable range into the configuration fields.

**Conflict analysis**
- Duplicate IP detection: same IP with different MACs in the ARP table.
- Duplicate NetBIOS detection: same name on different IPs.
- Blocked-access hosts: they answer ping but have both SMB and RDP closed.
- Orphaned ARP entry cataloging: host visible but no ARP record.
- Severity classification: `CRITICO` (active collision risk) or `AVISO` (anomaly requiring review).

**ARP tools**
- Full dump of the system ARP table.
- Local ARP cache flush with prior confirmation (requires administrator privileges).

**Activity log**
- Persistent session log of every operation performed.
- Levels: INFO, OK, WARN, ERROR.
- Export to `.txt` file.

**Data export**
- Conflict results exportable to CSV with timestamped file names.
- Activity log exportable to plain text.

**Interface**
- Native WPF, dark theme, zero third-party dependencies.
- Non-blocking scan through an independent Runspace with thread-safe queue communication.
- Real-time progress bar with discovered-host counter.
- Row coloring by state directly from the DataGrid `LoadingRow` event.

---

## Requirements

| Requirement | Detail |
|---|---|
| Operating system | Windows 10 / Windows 11 / Windows Server 2016 or higher |
| PowerShell | 5.1 or higher (included in Windows by default) |
| .NET Framework | 4.5 or higher (included in Windows 10+) |
| NetTCPIP module | Included by default since Windows 8 / Server 2012 |
| Privileges | Standard user for scanning. Administrator to flush the ARP cache |
| Connectivity | The machine must be on the same subnet or have routing to the scanned range |

No installation, no extra PowerShell modules, no internet access required.

---

## Installation and usage

### Direct download

```
git clone https://github.com/SergioGL-14/NetGhost.git
cd NetGhost
```

Or download `NetGhost.ps1` directly from the _Releases_ section.

### Running it

**Option 1 — From Windows Explorer**

Right-click `NetGhost.ps1` → _Run with PowerShell_.

If Windows blocks execution by policy, use option 2.

**Option 2 — From PowerShell with one-time bypass**

```powershell
powershell -ExecutionPolicy Bypass -File .\NetGhost.ps1
```

This parameter applies only to the current run; it does not change the system policy.

**Option 3 — From PowerShell ISE or VS Code**

Open the file and press F5, or run in the integrated terminal:

```powershell
. .\NetGhost.ps1
```

### Typical workflow

1. At startup, NetGhost detects the active network and preloads the subnet and range fields.
2. Review the detected values. Adjust the range if you only want to scan one specific segment.
3. Press **▶ ESCANEAR**. The scan runs in the background and results appear in real time.
4. When it finishes, go to **⚡ Conflictos** and press **ANALIZAR CONFLICTOS**.
5. Review the detected conflicts. Export to CSV if you need to document or escalate.
6. Use **Herramientas ARP** if you need to flush the cache or see the full table.
7. The **activity log** records everything that happened during the session and can be exported.

Button labels are shown as the interface displays them, which is in Spanish.

---

## Detailed functional description

### Network autodetection

At startup, NetGhost calls `Get-ActiveSubnet`, which uses `Get-NetIPConfiguration` to enumerate available adapters. Selection happens in two phases:

**Phase 1 — Adapter quality filtering**

Adapters matching any of these conditions are discarded:
- No IPv4 gateway defined (not the way out to the network).
- Status other than `Up`.
- Description matching: `Hyper-V`, `VMware`, `VirtualBox`, `Loopback`, `Teredo`, `isatap`, `Bluetooth`, `TAP`, `Tunnel`, `WAN Miniport`, `Microsoft Wi-Fi Direct`, `Kernel Debug`.

If no candidate survives the strict filter, a less restrictive fallback applies that only requires the adapter to be up and have an IP assigned.

**Phase 2 — Route metric selection**

Among valid candidates, the one with the lowest `RouteMetric + InterfaceMetric` sum wins. This is exactly the logic Windows uses to decide which interface routes traffic by default. On machines with Ethernet and Wi-Fi active simultaneously, it picks the right one in the vast majority of cases.

**Result**

The returned object carries network and broadcast addresses computed from the CIDR mask, the usable range limited to the displayed three-octet scan segment, local IP, CIDR prefix, interface alias and gateway. The interface keeps a three-octet field and allows scanning up to 254 hosts per run.

The **⬡ DETECTAR RED** button repeats the process at any time without restarting the app — useful when the machine changes networks between sessions.

---

### Network scan

The scan runs in a Runspace independent from the UI thread so it never blocks it. Communication between the Runspace and the interface uses a `ConcurrentQueue<PSObject>`, which is thread-safe by design.

**Per IP in the range:**

1. **Ping** — An ICMP echo request with 500 ms timeout via `System.Net.NetworkInformation.Ping`. Only `Success` continues.

2. **ARP lookup** — Queries the ARP table read once at scan start (a single read for the whole range). If the IP has an entry, its MAC is taken; otherwise marked `N/A`.

3. **Vendor identification** — First 3 bytes of the MAC (OUI) looked up in an embedded table of 20 vendors common in corporate environments. No external queries, no APIs.

4. **Name resolution** — First `nbtstat -A` looking for `<00> UNIQUE` records (NetBIOS machine name). If that fails, `[System.Net.Dns]::GetHostEntry` for reverse DNS. If both fail, returns `?`.

5. **Port check** — Asynchronous TCP connection attempt to ports 445 (SMB) and 3389 (RDP) with 600 ms timeout. Open or closed state recorded.

6. **Host classification:**
   - `OK` — Has MAC in ARP and at least one of the two ports reachable.
   - `WARN` — Has MAC but neither port answers.
   - `SIN_ARP` — Answers ping but has no entry in the ARP table.

**UI update:**

A single Runspace processes the range sequentially. A `DispatcherTimer` with a 250 ms interval drains the result queue on the UI thread and appends them to the `ObservableCollection` bound to the DataGrid. The grid updates automatically through binding. Progress bar and counters refresh on the same tick.

---

### Conflict analysis

The analysis works on data already gathered during the scan plus a fresh read of the system ARP table. It runs synchronously since it is fast by nature.

**Type 1 — Duplicate IP (CRITICO)**

The full ARP table is read and grouped by IP. If the same IP shows more than one distinct MAC, that is an active addressing conflict. It usually means two machines share a static IP, or a machine changed its network card without updating the DHCP reservation. It is the most serious situation because it causes intermittent packet loss that is hard to diagnose.

**Type 2 — Duplicate NetBIOS (CRITICO)**

Scan results are grouped by NetBIOS name. If the same name appears on more than one IP, there is a name collision on the network. In domain environments this can prevent the machine from authenticating properly or make shares unreachable.

**Type 3 — Blocked access (AVISO)**

Hosts answering ping with both 445 and 3389 closed. Could be a misconfigured firewall, a machine with its network profile set to public, or a non-Windows device (printer, NAS, managed switch) not exposing those services. Needs review but is not an active conflict.

**Type 4 — Missing ARP entry (AVISO)**

Hosts answering ping without a record in the local ARP table. Can happen when the machine sits on a different routed subnet, when ARP is being suppressed by some security agent, or when the entry expired between the ping and the ARP read. Worth investigating because it can hide an unauthorized machine.

---

### ARP tools

**View ARP table**

Runs `arp -a` and dumps the complete output into the text area of the tools page. Handy for quick manual inspection without leaving the app.

**Flush ARP cache**

Runs `netsh interface ip delete arpcache` after user confirmation. Requires PowerShell running with administrator privileges. Useful after resolving an IP conflict to force the system into rediscovering the correct MACs without waiting for ARP entry TTLs to expire (2 minutes by default on Windows).

---

### Activity log

Every relevant operation is logged with timestamp and level:

- `[·]` INFO — Normal startup, navigation and configuration operations.
- `[✔]` OK — Operations completed successfully.
- `[⚠]` WARN — Situations needing attention but not errors.
- `[✘]` ERROR — Operation failures.

The log is read-only during the session. It can be cleared manually or exported to `.txt` from the log page toolbar.

---

## Technical architecture

```
NetGhost.ps1
│
├── [UI thread – STA Dispatcher]
│   ├── WPF Window (XAML embedded in here-string)
│   ├── ObservableCollection → DataGrid binding
│   ├── DispatcherTimer (250ms) → drains ConcurrentQueue
│   └── Button events, navigation, export
│
└── [Independent Runspace – STA]
    ├── Ping range (sequential, timeout 500ms)
    ├── ARP lookup (table read once at start)
    ├── NetBIOS/DNS resolution
    ├── TCP port check 445, 3389 (async, timeout 600ms)
    └── Enqueue results → ConcurrentQueue<PSObject>
```

**Why a Runspace instead of Start-Job or Start-ThreadJob**

`Start-Job` serializes objects crossing the process boundary, which strips away the .NET types we need. `Start-ThreadJob` is not available on PowerShell 5.1 without installing the `ThreadJob` module. A Runspace with `BeginInvoke` is the native solution that works across every required version and allows sharing direct .NET object references, including the `ConcurrentQueue`.

**Why ConcurrentQueue instead of a Synchronized ArrayList**

`ConcurrentQueue<T>` is designed exactly for the producer-consumer pattern. The Runspace produces, the DispatcherTimer consumes. No explicit locks needed and `TryDequeue` is an atomic, non-blocking operation. A synchronized `ArrayList` would require a lock on every access and add needless complexity.

**Why embedded XAML instead of an external file**

To keep the script a single self-contained file. `XamlReader.Load()` parses the XAML at runtime. One limitation of this approach: `DataTemplate.Triggers` is not supported by PowerShell's partial parser (unlike Visual Studio's XAML compiler), so row coloring is delegated to the DataGrid `LoadingRow` event.

---

## Code structure

The script is divided into numbered, commented blocks:

```
BLOQUE 0  – Global configuration and shared variables
BLOQUE 1  – Get-ActiveSubnet function (network autodetection)
BLOQUE 2  – Scan functions: Get-ArpTable, Get-MACVendor, Start-NetworkScan
BLOQUE 3  – Analysis functions: Find-Conflicts, Clear-ArpCache
BLOQUE 4  – WPF interface XAML definition
BLOQUE 4b – Window load and control references
BLOQUE 4c – UI functions: Write-Log, Set-ActivePage, Set-ScanningState, Invoke-DetectNetwork
BLOQUE 4d – Sidebar navigation events
BLOQUE 4e – Detection and scan events
BLOQUE 4f – Conflict analysis events
BLOQUE 4g – ARP tools events
BLOQUE 4h – Log events
BLOQUE 4i – Initialization and startup
```

---

## Known limitations

**NetBIOS resolution**

`nbtstat -A` can take between 1 and 3 seconds per host on high-latency networks or when NetBIOS over TCP/IP is disabled. On networks with many hosts this lengthens the scan. A future improvement would be parallelizing name resolutions.

**Vendor OUI table**

The embedded table covers prefixes common in corporate environments but is not exhaustive. There is no query against the public IEEE registry. On sites with less common hardware, many vendors will show as `Desconocido`.

**Maximum range of 254 hosts per run**

Autodetection computes the correct network address for any IPv4 prefix. The interface keeps a maximum of 254 hosts per run; on networks larger than /24 the scan must be repeated per three-octet segment.

**Conflict detection based on the local ARP table**

Duplicate IP analysis relies on the ARP table of the machine running NetGhost, not on traffic capture. That means it only detects conflicts that produced ARP entries on that particular machine. A conflict between two hosts that never talked to the analysis machine stays invisible.

**Same subnet or routing required**

Ping and TCP checks must reach the target hosts. On networks with VLANs lacking inter-VLAN routing, only hosts on the local VLAN will appear.

**No persistence between sessions**

Scan results and detected conflicts are not saved when the app closes, unless manually exported to CSV or txt beforehand.

---

## Tests

`Tests/NetGhost.Tests.ps1` checks the script statically (parseability without loading WPF) and then extracts the pure functions — `Get-IPv4NetworkInfo`, `Test-ScanConfiguration`, `Find-Conflicts` — via AST, loading them without touching the WPF startup code. With those it validates CIDR math (/25 and /16 cases), scan configuration validation and duplicate-IP detection against a synthetic ARP table. Run it after touching any of those areas:

```powershell
powershell -ExecutionPolicy Bypass -File .\Tests\NetGhost.Tests.ps1
```

CI runs the same check on every push.

---

## License

This project is distributed under the MIT license. See the `LICENSE` file for details.
