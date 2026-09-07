# ScanTouch Antivirus — Zero-Dependency Standalone Scanner

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Zero-Dependency](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Signatures](https://img.shields.io/badge/Signatures-88%20Multi--Indicator%20Rules-orange.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**ScanTouch** is a host-based, high-performance command-line antivirus scanner written in pure **modern C++17**. It delivers comprehensive static threat detection, behavioral script analysis, and PE binary heuristics within a **single standalone C++ source file**—requiring **zero external libraries** (no OpenSSL, no SQLite, no YARA, no Boost).

It compiles in seconds on **Windows**, **Linux**, and **macOS** with any standard C++17 compiler.

---

## Table of Contents

- [Key Highlights](#key-highlights)
- [How It Works (Internal Architecture)](#how-it-works-internal-architecture)
  - [Detection Pipeline](#detection-pipeline)
  - [Native Cryptographic Hashing](#1-native-cryptographic-hashing-pure-c17)
  - [Shannon Entropy Engine](#2-shannon-entropy-engine)
  - [Sub-Linear Boyer-Moore-Horspool Search](#3-sub-linear-boyer-moore-horspool-search)
  - [XOR-0x5A Signature Obfuscation](#4-xor-0x5a-signature-obfuscation)
  - [Target-Aware Extension Filtering](#5-target-aware-extension-filtering-istargetmatch)
  - [Multi-Indicator AND-Logic Rules](#6-multi-indicator-and-logic-rules)
  - [PE Binary Heuristics](#7-pe-binary-heuristics)
  - [Windows OS Hardening](#8-windows-os-hardening)
- [Threat Detection Coverage](#threat-detection-coverage)
- [Building & Compilation](#building--compilation)
- [Command Guide & CLI Reference](#command-guide--cli-reference)
  - [Command Syntax](#command-syntax)
  - [CLI Flags & Options](#cli-flags--options)
  - [Practical Command Recipes](#practical-command-recipes)
  - [Exit Codes](#exit-codes)
- [Project Structure](#project-structure)
- [License](#license)

---

## Key Highlights

* **Zero External Dependencies**: Standard C++17 library only. No package managers (`vcpkg`, `apt`, `brew`) required.
* **Native Crypto**: Built-in SHA-256 (FIPS 180-4) and MD5 (RFC 1321) implementations.
* **Fast Sub-Linear Scanning**: Boyer-Moore-Horspool (BMH) pattern search with case-insensitive ASCII folding.
* **88 Multi-Indicator Behavioral Signatures**: Detects PowerShell keyloggers, AMSI bypasses, LOLBins, reverse shells, certutil abuse, Defender tampering, and ransomware payloads.
* **Zero False-Positive Target Filtering (`isTargetMatch`)**: Scopes script rules strictly to executable extensions (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.py`, `.sh`), insulating licenses, JSON configs, sourcemaps, and web bundles.
* **PE Heuristic Engine**: Detects packed/encrypted zero-day executables using entropy scoring (> 7.6), known packer sections (UPX, Themida, ASPack, MPRESS), and dynamic loader import profiling.
* **Multi-Threaded Architecture**: Automatic hardware concurrency thread pool for high-throughput disk scanning.
* **Windows Hardened**: Automatic symlink/junction loop avoidance and UTF-8 / ANSI VT console processing.

---

## How It Works (Internal Architecture)

### Detection Pipeline

Every file scanned by ScanTouch passes through a staged inspection pipeline:

```
                  Target File
                      │
                      ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 1. Native Crypto Hashing & File Identification            │
  │    • Compute SHA-256 (FIPS 180-4)                         │
  │    • Compute MD5 (RFC 1321)                               │
  │    • Compute Shannon Entropy                              │
  │    • Identify File Type via Magic Bytes (PE, ELF, TEXT)   │
  └───────────────────────────┬───────────────────────────────┘
                              │
                              ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 2. Stage 1: Exact Hash Database Lookup (0% False Positives)│
  │    • Instant match against known ransomware / Trojan hashes│
  └───────────────────────────┬───────────────────────────────┘
                              │ (If hash not matched)
                              ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 3. Stage 2: Binary Shellcode Detection (PE / ELF / BINARY) │
  │    • Boyer-Moore-Horspool search for raw shellcode stubs  │
  │    • Meterpreter x86, Cobalt Strike Beacon x64            │
  └───────────────────────────┬───────────────────────────────┘
                              │
                              ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 4. Stage 3: Multi-Indicator Signature Matching            │
  │    • isTargetMatch(): Filter by executable extension       │
  │    • xd(): XOR-0x5A decode pattern indicators in RAM      │
  │    • bmhFindNoCase(): Case-insensitive BMH search         │
  │    • AND-Logic: ALL indicators in rule must match         │
  └───────────────────────────┬───────────────────────────────┘
                              │
                              ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 5. Stage 4: PE Binary Heuristics (Windows Executables)     │
  │    • Packer section signatures (UPX0, .aspack, .themida)  │
  │    • High entropy threshold (> 7.6)                       │
  │    • Dynamic loader-only import analysis (LoadLibrary)    │
  └───────────────────────────┬───────────────────────────────┘
                              │
                              ▼
                     Scan Result & Alert
              [CLEAN] / [SUSPECT] / [MALWARE]
```

---

### 1. Native Cryptographic Hashing (Pure C++17)
To remain 100% self-contained without linking OpenSSL:
* **MD5 (RFC 1321)**: Processes 64-byte blocks through four non-linear auxiliary functions ($F, G, H, I$), modular additions, and 64 transform steps.
* **SHA-256 (FIPS 180-4)**: Computes 256-bit digests using the 64-entry constant array $K[64]$, message scheduler expansions ($\sigma_0, \sigma_1$), and 64 compression rounds ($\Sigma_0, \Sigma_1, \text{Ch}, \text{Maj}$).

### 2. Shannon Entropy Engine
Entropy measures the randomness of information in a byte stream:

$$H(X) = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$

| Entropy Score | Expected Content Type |
|:---:|---|
| **$3.5 - 5.0$** | Source code, scripts, plain text documentation |
| **$6.0 - 6.8$** | Standard compiled machine code (PE/ELF executables) |
| **$> 7.6$** | Heavily packed, compressed, or encrypted malware payloads |

### 3. Sub-Linear Boyer-Moore-Horspool Search
Searching multi-gigabyte directories requires sub-linear pattern matching:
* Builds a 256-byte bad-character jump table for each signature.
* On character mismatches, it skips ahead by the distance to the next possible alignment, scanning large files rapidly without inspecting every byte.
* `bmhFindNoCase` implements case-folding lookups (`table[c >= 'A' && c <= 'Z' ? c + 32 : c]`), allowing accurate detection of PowerShell or batch scripts regardless of casing variations (e.g., `GeTaSyNcKeYsTaTe` vs `getasynckeystate`).

### 4. XOR-0x5A Signature Obfuscation
All signature indicators in the source code are stored as byte arrays XOR-encoded with key `0x5A`:
```cpp
static std::string xd(const char* enc, size_t len) {
    std::string out(len, '\0');
    for(size_t i = 0; i < len; i++) out[i] = enc[i] ^ 0x5A;
    return out;
}
```
> [!NOTE]
> **Why XOR Obfuscation?**
> If signatures were stored as plain strings in C++ source code or binary data, scanning the scanner executable, its source file, or documentation would trigger self-detection false positives. With XOR encoding, signature patterns exist as plain text **only in volatile RAM** during evaluation.

### 5. Target-Aware Extension Filtering (`isTargetMatch`)
A common issue in signature scanners is false alarms on non-executable files (e.g., OpenSSH licenses mentioning `ssh -R`, or VS Code bundles mentioning `clipboard`).
ScanTouch eliminates this with target-aware filtering:

* `PS1` rules **only** evaluate files ending in `.ps1`, `.psm1`, `.psd1`.
* `BAT` rules **only** evaluate files ending in `.bat`, `.cmd`.
* `VBS` rules **only** evaluate files ending in `.vbs`, `.vbe`, `.wsf`.
* `HTA` rules **only** evaluate files ending in `.hta`.
* `PY` rules **only** evaluate files ending in `.py`, `.pyw`.
* `SH` rules **only** evaluate files ending in `.sh`, `.bash`, `.zsh`.
* `PE` rules **only** evaluate files with genuine Windows Portable Executable headers (`MZ` + `PE\0\0`).
* Plain documentation (`.txt`), JSON (`.json`), sourcemaps (`.map`), databases (`.db`), and TypeScript declarations (`.d.ts`) are **automatically shielded from script execution rules**.

### 6. Multi-Indicator AND-Logic Rules
Rather than flagging single generic keywords, every rule requires **multiple correlated indicators**:
* *PowerShell Keylogger*: Requires `GetAsyncKeyState` **AND** `GetKeyboardState` (or `MapVirtualKey` / `ToUnicode`).
* *Defender Tampering*: Requires `Set-MpPreference` **AND** `DisableRealtimeMonitoring` **AND** `$true`.
* *Certutil Abuse*: Requires `certutil` **AND** `-urlcache` **AND** `-split` **AND** `-f`.

### 7. PE Binary Heuristics
Analyzes Windows binaries (`PE`) for zero-day packer and dropper traits:
1. **Known Packer Sections**: Checks for section names `UPX0`, `UPX1`, `.aspack`, `.themida`, `.vmp0`, `MPRESS` (+45 points).
2. **High Entropy Threshold**: Flagged if section entropy $> 7.6$ (+35 points).
3. **Loader-Only Imports**: Checks if dynamic loading APIs (`LoadLibraryA/W`, `GetProcAddress`) are imported without typical OS APIs (`CreateFileW`, `CreateWindowExW`, `RegOpenKeyExW`) (+20 points).
* When cumulative score $\ge 80$, the binary is flagged as `Packer.Generic.Packed` or `Heuristic.SuspiciousPacker`.

### 8. Windows OS Hardening
* **Directory Junction & Symlink Protection**: Uses `it->symlink_status()` to identify and skip directory reparse points (preventing infinite recursion crashes on Windows links like `C:\Users\Default User` or `C:\Users\All Users`).
* **Console UTF-8 & ANSI VT**: Calls `SetConsoleOutputCP(CP_UTF8)` and enables `ENABLE_VIRTUAL_TERMINAL_PROCESSING` at startup, ensuring clean Unicode box characters (`╔═╗`, `→`, `⚠`) and ANSI colors render properly in Windows CMD and PowerShell.

---

## Threat Detection Coverage

| Category | Threat Name / Rule | Indicators & Detection Mechanism | Target |
|:---|:---|:---|:---:|
| **PowerShell** | `Spyware.PowerShell.Keylogger` | Win32 API hooks: `GetAsyncKeyState` + `GetKeyboardState` / `MapVirtualKey` / `ToUnicode` | `.ps1` |
| **PowerShell** | `HackTool.PowerShell.AmsiBypass` | AMSI memory patching: `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer` | `.ps1` |
| **PowerShell** | `Script.PowerShell.DownloadCradle` | Hidden cradles: `Net.WebClient` + `DownloadString` / `DownloadData` + `IEX` | `.ps1` |
| **PowerShell** | `Trojan.PowerShell.DisableDefender` | Tampering: `Set-MpPreference` + `DisableRealtimeMonitoring` + `$true` | `.ps1`, `.cmd` |
| **PowerShell** | `Backdoor.PowerShell.ReverseShell` | TCP redirection: `Net.Sockets.TCPClient` + `GetStream` | `.ps1` |
| **Batch / CMD** | `Script.Batch.CertutilDownload` | Remote fetch: `certutil` + `-urlcache` + `-split` + `-f` / `http` | `.bat`, `.cmd` |
| **Batch / CMD** | `Trojan.Script.CertutilDecode` | In-memory decode: `certutil` + `-decode` | `.bat`, `.cmd` |
| **Batch / CMD** | `Trojan.Script.BitsadminDownload` | Background transfer: `bitsadmin` + `/transfer` + `/download` | `.bat`, `.cmd` |
| **Batch / CMD** | `Ransom.Script.ShadowDelete` | Ransomware prep: `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete` | `.bat`, `.cmd` |
| **Batch / CMD** | `Exploit.LOLBin.Mshta` | LOLBin execution: `mshta` + `vbscript:Execute` / `javascript:` | `.bat`, `.cmd` |
| **Batch / CMD** | `Exploit.LOLBin.Rundll32` | Proxy execution: `rundll32` + `javascript:` / `URL.dll,FileProtocolHandler` | `.bat`, `.cmd` |
| **Batch / CMD** | `Persistence.Script.Schtasks` | Scheduled persistence: `schtasks` + `/create` + `/sc onlogon` / `/sc onidle` | `.bat`, `.cmd` |
| **VBS / HTA** | `Script.VBS.XMLHTTPDropper` | Payload droppers: `MSXML2.XMLHTTP` + `ADODB.Stream` + `SaveToFile` | `.vbs` |
| **VBS / HTA** | `Script.HTA.Dropper` | HTA droppers: `<script` + `WScript.Shell` + `powershell` | `.hta` |
| **Python** | `Backdoor.Python.ReverseShell` | Interactive shell: `socket.socket` + `subprocess.call` + `/bin/sh` | `.py` |
| **Python** | `Spyware.Script.SmtpExfiltration` | Mail exfiltration: `smtplib.SMTP` + `sendmail` + `password` | `.py` |
| **Exfiltration** | `Spyware.Script.SmtpExfiltration` | SMTP credentials & data exfil: `Net.Mail.SmtpClient` + `NetworkCredential` | `.ps1`, `.vbs` |
| **Exfiltration** | `Spyware.Script.DiscordWebhook` | Webhook stealer: `api/webhooks/` + `Invoke-RestMethod` | Script |
| **Hijackers** | `Spyware.Script.ClipboardHijacker` | Crypto address replace: `Set-Clipboard` / `pyperclip` + `0x` regex | `.ps1`, `.py` |
| **Cryptominers**| `Trojan.Script.Cryptominer` | Pool configs: `stratum+tcp://`, `stratum+ssl://`, `xmrig` | `.sh`, `.bat` |
| **Linux / Bash**| `Backdoor.RevShell.Bash` | Socket redirection: `/dev/tcp/` + `exec 5<>` / `bash -i` | `.sh` |
| **Linux / Bash**| `Backdoor.NetCat.Shell` | Traditional backdoors: `nc -e /bin/sh`, `nc.traditional` | `.sh` |
| **Linux / Bash**| `Backdoor.Socat.Shell` | Raw TTY shells: `socat exec:` + `pty,raw,echo=0` | `.sh` |
| **Tunnels** | `Backdoor.SSH.ReverseTunnel` | Port forward backdoors: `ssh -R` / `plink -R` + `-N` / `-pw` | Script |
| **Tunnels** | `Backdoor.SSH.DynamicSocks` | SOCKS proxy pivots: `ssh -D` + `-f` + `-N` | `.sh` |
| **Executables** | `Trojan.Meterpreter.x86` | Metasploit reverse shellcode byte sequence | Binary |
| **Executables** | `Trojan.CobaltStrike.Beacon` | Cobalt Strike Beacon x64 shellcode sequence | Binary |
| **Executables** | `Ransom.WannaCry` | WannaCry ransomware signatures & exact file hashes | Binary |
| **Executables** | `Ransom.LockBit` / `Locky` | LockBit 3.0 & Locky ransomware markers | Any |
| **Executables** | `Trojan.Emotet` / `AgentTesla` | Banking Trojans & credential stealers | Binary |
| **Executables** | `Trojan.Mirai.Bot` | Mirai IoT botnet byte patterns | ELF |
| **Test Sample** | `EICAR-Test-File` | Standard benign 68-byte EICAR antivirus verification string | Any |

---

## Building & Compilation

ScanTouch has **zero external library dependencies**. To build, all you need is a C++17 compatible compiler:

### Windows (MinGW / GCC)
```cmd
g++ -std=c++17 -O2 -o scantouch.exe scantouch.cpp
```

### Windows (Microsoft Visual C++ / MSVC)
Open **x64 Native Tools Command Prompt for VS** and run:
```cmd
cl /std:c++17 /O2 /EHsc scantouch.cpp /Fe:scantouch.exe
```

### Linux (GCC or Clang)
```bash
g++ -std=c++17 -O2 -o scantouch scantouch.cpp
# or
clang++ -std=c++17 -O2 -o scantouch scantouch.cpp
```

### macOS (Clang / Apple Silicon & Intel)
```bash
clang++ -std=c++17 -O2 -o scantouch scantouch.cpp
```

---

## Command Guide & CLI Reference

### Command Syntax

```bash
scantouch scan <path> [options]
scantouch version
```

### CLI Flags & Options

| Flag | Argument | Description | Default |
|:---|:---:|:---|:---:|
| `--threads` | `<N>` | Number of concurrent scanning threads | Auto (CPU cores) |
| `--no-recursive` | — | Scan only the specified directory without entering subdirectories | Recursive |
| `--no-heuristic` | — | Disable the PE binary heuristic & packer detection engine | Enabled |
| `--json` | — | Output machine-readable JSON array for CI/CD or SIEM ingestion | Formatted Text |
| `--verbose` | — | Show every file scanned including `[CLEAN]` files and entropy scores | Threats Only |
| `--no-skip-trusted` | — | Force scanning Windows Defender definitions and system directories | Skipped |
| `--max-size` | `<MB>` | Skip files larger than the specified size in megabytes | No limit |
| `--exclude-ext` | `<.ext>` | Exclude files matching this extension (repeatable flag) | None |
| `--exclude-path` | `<sub>` | Exclude paths containing this substring (repeatable flag) | None |

---

### Practical Command Recipes

#### 1. Basic Directory or File Scan
Scan a user folder or specific file:
```bash
# Linux / macOS
./scantouch scan /home/user/Downloads

# Windows
.\scantouch.exe scan C:\Users\ <username> \Downloads
```

#### 2. Scan Whole User Drive with Multi-Threading
Run a fast scan across all files utilizing 8 parallel threads:
```bash
.\scantouch.exe scan C:\Users --threads 8
```

#### 3. Exclude Specific Extensions & Paths
Skip temporary build folders, Git metadata, or large log files:
```bash
.\scantouch.exe scan C:\Users --exclude-path node_modules --exclude-path .git --exclude-ext .log --exclude-ext .iso
```

#### 4. Export Machine-Readable JSON
Generate structured JSON output to pipe into security analytics, SIEM, or a file:
```bash
# Windows PowerShell
.\scantouch.exe scan C:\Users --json > scan_report.json

# Linux
./scantouch scan /var/www --json > scan_report.json
```

**JSON Output Example:**
```json
[
{
  "file": "C:\\Users\\vboxuser\\Downloads\\p.ps1",
  "sha256": "3a7b9c1d2e...",
  "md5": "a8f5c2...",
  "type": "TEXT",
  "size": 2048,
  "entropy": 4.82,
  "threats": [
    {"name": "Spyware.PowerShell.Keylogger", "severity": "HIGH", "score": 0, "details": "Signature match (2 indicators)"},
    {"name": "Spyware.Script.SmtpExfiltration", "severity": "HIGH", "score": 0, "details": "Signature match (3 indicators)"}
  ]
}
]
```

#### 5. Verify Scanner with Test Sample (EICAR)
Confirm the engine is functioning without real malware:
```bash
./scantouch scan tests/samples
```

#### 6. Fast Script-Only Scan (Skip Heavy Files)
Skip large media/disk images to quickly audit scripts and executables:
```bash
.\scantouch.exe scan C:\Users --max-size 50
```

#### 7. Verbose Inspection
Audit all files and display individual entropy calculations:
```bash
./scantouch scan ./my_project --verbose
```

---

### Exit Codes

ScanTouch returns standard process exit codes for integration with automation scripts, GitHub Actions, and CI/CD pipelines:

| Exit Code | Meaning | Action Recommended |
|:---:|:---|:---|
| **`0`** | **CLEAN** | No threats detected. Safe to proceed. |
| **`1`** | **THREATS DETECTED** | One or more files matched malware or suspicious heuristics. |
| **`2`** | **ERROR** | Invalid arguments, path does not exist, or permission denied. |

---

## Project Structure

```
Anti-Virus/
├── scantouch.cpp  # Complete standalone scanner (zero dependencies)
├── tests/
│   └── samples/
│       └── eicar.com        # Standard benign 68-byte EICAR test sample
└── README.md                # Comprehensive documentation & command guide
```

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
