# ICS-SpecGen

**Evidence-driven supply-chain requirements for PLC firmware**

ICS-SpecGen is a lightweight Python command-line tool. You give it a PLC firmware image, such as an SD-card `.img` or a `.zip`/`.7z` archive. It then:

1. **extracts security evidence** from the binary, entirely on Windows (no Docker, WSL or Linux VM),
2. **maps the evidence** to IEC 62443 requirements using a small, explicit ruleset, and
3. **generates three outputs:**
   - a machine-readable **OPA/Rego gate policy**
   - a human-readable **procurement checklist**
   - an **acceptance report** that compares firmware versions

```
+--------------------------+       +---------------------------+       +-------------------------------+
|  Firmware binary         |  ==>  |  specgen (Python)         |  ==>  |  Verifiable outputs           |
|  - WAGO PFC .img         |       |  - unpack (7-Zip)         |       |  - gate_policy.rego (+ data)  |
|  - RevPi .zip            |       |  - ELF hardening (pyelf)  |       |  - procurement_checklist.md   |
|  - any Linux rootfs img  |       |  - SBOM (syft + fallback) |       |  - acceptance_report.md       |
|                          |       |  - CVEs (grype)           |       |  - evidence.json / findings   |
|                          |       |  - integrity + config     |       |                               |
|                          |       |  - ruleset.yaml mapping   |       |                               |
+--------------------------+       +---------------------------+       +-------------------------------+
```

---

## 1. Goals

| # | Goal | Success criterion |
|---|------|-------------------|
| G1 | Produce device-level security evidence from a firmware binary using free tools on Windows only | `specgen collect` produces `evidence.json` for both target firmwares with no Linux dependency |
| G2 | Translate low-level findings into supplier requirements traceable to IEC 62443 | Every generated clause cites a rule ID, the evidence that triggered it, and the IEC 62443 reference(s) |
| G3 | Emit an executable acceptance gate | `opa eval` on the generated policy returns `allow=false` for the insecure firmware and `allow=true` (or fewer violations) for the baseline |
| G4 | Demonstrate the approach on real vendor firmware | Comparison of an old and a new WAGO PFC firmware, written up in `acceptance_report.md` |

## 2. Scope and non-goals

**In scope**
- Linux-based PLC firmware images (ELF user space)
- 4 requirement categories:
  - memory-safety hardening
  - dependency hygiene
  - cryptographic integrity
  - secure defaults / attack surface
- 2 firmwares in the main evaluation (1 older/insecure, 1 newer/hardened baseline), plus 1 optional secondary pair
- Static analysis only: the firmware is never executed

**Out of scope (deliberately)**
- TPM/TCG attestation and hardware roots of trust. We only record whether evidence of a signing/verification *mechanism* exists.
- Dynamic analysis, emulation and fuzzing
- Decrypting encrypted firmware
- Proprietary PLC logic formats (CODESYS/IEC 61131-3 application code)
- Vendor update containers, which are v1 stretch goals: WAGO `.wup`, Phoenix Contact `.raucb`

---

## 3. Architecture and data flow

```
 firmware.img / .zip / .7z
          │
          ▼
 ┌──────────────────┐   recursive: archive → disk image → partitions → filesystems
 │ unpack.py        │   (7z.exe handles zip/7z/MBR/GPT/FAT/ext2-4/SquashFS/CramFS)
 └────────┬─────────┘
          ▼  work/<name>/rootfs/   (the largest Linux-looking tree is picked as rootfs)
 ┌────────┴──────────────────────────────────────────────────────────────┐
 │ hardening.py   sbom.py        vulns.py       integrity.py   config_audit.py │
 │ (pyelftools)   (syft.exe +    (grype.exe /   (sha256,       (shadow, sshd,  │
 │                opkg/dpkg      OSV fallback)  signature      inetd, keys)    │
 │                parser)                       indicators)                    │
 └────────┬──────────────────────────────────────────────────────────────┘
          ▼
   evidence.json  (one normalized document per firmware)
          │
          ▼
 ┌──────────────────┐   rules/ruleset.yaml
 │ rules.py         │── evaluate each rule → PASS / FAIL / N/A with evidence pointers
 └────────┬─────────┘
          ▼  findings.json
 ┌──────────────────┐
 │ render.py        │── procurement_checklist.md
 │ (Jinja2)         │── gate_policy.rego + gate_data.json   ──►  opa.exe eval / opa test
 │                  │── acceptance_report.md (compares N firmwares)
 └──────────────────┘
```

**Key design choices**

- **Normalized evidence.** No stage after `collect` reads raw tool output. That keeps the rules and the Rego policy independent of whether syft or the fallback parser was used.
- **The policy is data-driven.** The Rego logic is generic. Thresholds and the accepted-baseline metrics live in `gate_data.json`, so a new baseline means new data, not a new policy.
- **Every output line is traceable.** Each checklist clause and each Rego violation carries `rule_id`, `iec62443_refs` and an `evidence_ref` (a JSON pointer into `evidence.json`).

---

## 4. Firmware targets

> You will download these yourself. All links below were checked against the vendors' public release pages in September 2026.

### 4.1 Primary pair: WAGO PFC100/PFC200 (Linux-based PLC)

WAGO publishes official PFC controller firmware on GitHub: <https://github.com/WAGO/pfc-firmware/releases>. The images are raw SD-card images (`.img`) of an embedded Linux (PTXdist-based) system. That makes them ideal for this tool: the ELF binaries are real, the packages are real, and they are publicly redistributable.

| Role | Release | File | Size | Date | Direct link |
|------|---------|------|------|------|-------------|
| **Insecure target** | FW13 v03.01.07 | `WAGO_FW0750-8xxx_V030107_IX13_r40667.img` | 182.5 MB | 2019-07 | https://github.com/WAGO/pfc-firmware/releases/download/v3.1.7/WAGO_FW0750-8xxx_V030107_IX13_r40667.img |
| **Hardened baseline** | FW24 v04.02.13 (PFC G2) | `PFC-G2-Linux_sd_V040213_24_r74297.img` | 287.3 MB | 2023-06 | https://github.com/WAGO/pfc-firmware/releases/download/v04.02.13-24/PFC-G2-Linux_sd_V040213_24_r74297.img |
| Alternative baseline (same 8x1x HW family) | FW22 v03.10.10 SP1 | `WAGO_FW0750-8x1x_V031010_IX22_SP1_r71749.img` | 287.3 MB | 2023-08 | https://github.com/WAGO/pfc-firmware/releases/download/v03.10.10-22/WAGO_FW0750-8x1x_V031010_IX22_SP1_r71749.img |
| Release notes (FW13) | – | `2019-07-10.ReleaseNotes_750-8xxx.pdf` | 0.9 MB | – | https://github.com/WAGO/pfc-firmware/releases/download/v3.1.7/2019-07-10.ReleaseNotes_750-8xxx.pdf |
| Release notes (FW24) | – | `2023-03-28.ReleaseNotes_750-8x1x.pdf` | 1.4 MB | – | https://github.com/WAGO/pfc-firmware/releases/download/v04.02.13-24/2023-03-28.ReleaseNotes_750-8x1x.pdf |

**Why FW13 is a good "insecure" target.** Cisco Talos published several vulnerabilities in the PFC200 `iocheckd` ("I/O-Check") service that affect firmware 03.01.07(13). They include:
- an information disclosure of uninitialised stack data (CVE-2019-5073 / TALOS-2019-0862)
- heap buffer overflows (e.g. CVE-2019-5079, CVE-2019-5082)
- denial-of-service and factory-restore issues that reset credentials to documented defaults (e.g. TALOS-2019-0872)

These give us **ground truth** to test against: a working pipeline should flag `iocheckd` and the old dependency set.

**Caveat, which should be reported in the write-up.** FW24 targets PFC **G2** hardware, while FW13 is the older multi-device `8xxx` image. If you need the comparison to hold hardware constant, use FW22 (8x1x) as the baseline instead. Otherwise, state the hardware-generation confounder explicitly.

Other WAGO releases on the same page offer more data points if you want a longitudinal series: FW16, FW17, FW18, FW19 and FW21. Their `.7z` assets contain SD images.

### 4.2 Secondary pair (optional): Revolution Pi (KUNBUS), a Raspberry-Pi-based industrial PLC

These are Debian-based, so syft's dpkg cataloguer and grype's Debian matching work very well. They are useful to show that the tool generalises beyond WAGO.

| Role | File | Link |
|------|------|------|
| Old | `2021-07-01-revpi-buster.zip` | https://packages.revolutionpi.com/buster/2021-07-01-revpi-buster.zip |
| New | `revpi13.0-trixie-arm64-lite.zip` (≈ 428 MB, MD5 `c365097292ba93c11922b2c414d8192d`) | https://revolutionpi.com/fileadmin/downloads/images/revpi13.0-trixie-arm64-lite.zip |

Download page and archive index: <https://revolutionpi.com/en/support/downloads>

### 4.3 Considered but not used for the main evaluation

| Source | Why not primary |
|--------|-----------------|
| Phoenix Contact PLCnext AXC F 2152 (`.raucb` update bundle) | Downloaded through the Phoenix Contact Download Center rather than a stable direct URL. RAUC bundles are signed SquashFS, which is a good **positive** example for the integrity category. A good stretch target. |
| Siemens SIMATIC IOT2050 (`meta-iot2050`) | The GitHub releases carry no image assets; the images sit behind the Siemens portal. |
| PLC-BEAD dataset (OpenPLC/CODESYS compiled PLC programs) | These are compiled *PLC programs*, not firmware images. Out of scope. |
| Your own `ESP32-PLC` (in this folder) | Bare-metal (ESP-IDF), so Linux checks such as PIE/RELRO do not apply. See the stretch goal in §15. |

---

## 5. Windows toolchain setup

Everything runs natively on Windows 10/11 (x64).

| Tool | Purpose | Install |
|------|---------|---------|
| Python ≥ 3.10 | specgen itself (3.10.11 is already installed) | – |
| `pyelftools`, `PyYAML`, `Jinja2`, `jsonschema` | ELF parsing, ruleset, templates, schema validation | `pip install -r requirements.txt` |
| 7-Zip (`7z.exe`) | Unpack zip/7z, MBR/GPT disk images, FAT, ext2/3/4, SquashFS, CramFS | https://www.7-zip.org/, or `winget install 7zip.7zip` |
| syft (`syft.exe`) | CycloneDX SBOM from the extracted rootfs | `syft_<ver>_windows_amd64.zip` from https://github.com/anchore/syft/releases |
| grype (`grype.exe`) | CVE matching against the SBOM | `grype_<ver>_windows_amd64.zip` from https://github.com/anchore/grype/releases. Run `grype db update` once while online. |
| OPA (`opa.exe`) | Evaluate and test the generated Rego | https://github.com/open-policy-agent/opa/releases (`opa_windows_amd64.exe`, rename to `opa.exe`) |
| *(optional)* `checksec.py` | An independent LIEF-based cross-check of our hardening results | `pip install checksec.py` |

Put the `.exe` files in `ICS-SpecGen/tools/bin/` or on `PATH`. `specgen doctor` checks what is available and which fallbacks will be used.

**Windows specifics to handle**
- **Symlinks.** Linux rootfs trees contain many symlinks (`libfoo.so -> libfoo.so.1.2`). 7-Zip cannot create them without Windows **Developer Mode** or admin rights. specgen passes `-snl` when possible; otherwise it records the symlink targets in a side table. The analysis only walks regular files, so correctness is unaffected.
- **Case-insensitive filesystem.** Files that differ only in case are rare in rootfs trees, but they collide on Windows. Log a warning and keep both, with a suffix.
- **Path length.** Extract under a short root such as `C:\sg\work\` or enable long paths.
- **Antivirus.** Defender may quarantine files from the extracted rootfs (busybox, netcat). Add an exclusion for the work directory.

---

## 6. Evidence collection: module by module

### 6.1 `unpack.py`
1. Hash the input image (SHA-256, SHA-512) **before** touching it.
2. Unpack recursively with `7z x`. Stop at depth 4 or when no new container is found.
3. Handle layers such as: `.zip`/`.7z` → `.img` → partition files (`0.fat`, `1.img`, …) → ext/SquashFS contents.
4. Detect the rootfs by scoring each extracted tree on the presence of `etc/`, `bin/`, `lib/`, `usr/` and `sbin/init`. Keep the best one. If there are several rootfs partitions (A/B update schemes), record each and analyse the primary.
5. Output `unpack_manifest.json`, listing the layers, partition types, the chosen rootfs and any errors.

### 6.2 `hardening.py`: our own checksec, using pyelftools
For every regular file with the ELF magic `\x7fELF`:

| Property | Detection logic |
|----------|-----------------|
| Class | `ET_EXEC`, or `ET_DYN` with `PT_INTERP` = executable. `ET_DYN` without `PT_INTERP` = shared lib. Kernel modules (`.ko`) are counted separately. |
| **NX** | `PT_GNU_STACK` exists and its flags lack `PF_X`. If it is missing, record `unknown` (and treat it as *not* NX for scoring). |
| **PIE** | Executable with `ET_DYN`, or `DT_FLAGS_1 & DF_1_PIE` |
| **RELRO** | `PT_GNU_RELRO` → partial. Adding `DT_BIND_NOW`, `DT_FLAGS & DF_BIND_NOW` or `DT_FLAGS_1 & DF_1_NOW` → full. |
| **Stack canary** | `.dynsym` or `.symtab` references `__stack_chk_fail` or `__stack_chk_guard` (ARM uses the guard symbol). |
| **FORTIFY_SOURCE** | Imports any `__*_chk` symbol, e.g. `__memcpy_chk` or `__sprintf_chk` |
| RPATH/RUNPATH | `DT_RPATH` or `DT_RUNPATH` present, and whether it points to a writable/relative path |
| Stripped | No `.symtab` |
| Arch | `e_machine` (ARM, AArch64, x86-64 …) |

The module computes both per-binary results and **aggregate ratios**, split into *all executables*, *network-facing daemons* and *shared libraries*. A daemon counts as network-facing if it appears in init scripts or systemd units, or if it imports `bind`/`listen`/`accept`. The network-facing split matters: a missing canary in `iocheckd` counts for more than one in a CLI tool.

Output: `hardening.json`. The per-binary records use checksec-compatible keys, so the results can be compared with `checksec.py`.

### 6.3 `sbom.py`
1. **Primary:** `syft dir:<rootfs> -o cyclonedx-json=sbom.syft.cdx.json`. This covers dpkg (RevPi), binary classifiers (BusyBox, OpenSSL, Python, …) and language packages.
2. **Built-in fallback / supplement:** parse the package databases that syft may not cover:
   - `usr/lib/opkg/status`, `var/lib/opkg/status`, `usr/lib/ipkg/status` (PTXdist/WAGO)
   - `var/lib/dpkg/status` (if syft is absent)
3. **Version-string carving:** for well-known components that are often vendored:
   - `BusyBox v1.x.y`
   - `OpenSSL 1.0.2x`
   - Linux kernel version (from `/lib/modules/<ver>/` or the zImage banner)
   - `libmodbus`
   - CODESYS runtime version strings
4. **Merge and dedupe** by (name, version). Give every component a `purl` and a best-effort CPE, since grype matches opkg/generic components through CPEs.
5. Record `sbom_stats`: component count, the share of components with a version, and the share with a CPE or purl.

Output: `sbom.cdx.json` (CycloneDX 1.5), with a `properties` field stating which source found each component.

### 6.4 `vulns.py`
- **Primary:** `grype sbom:sbom.cdx.json -o json`. This runs offline after one `grype db update`.
- **Fallback:** the OSV.dev batch API (`/v1/querybatch`) for components with a purl. It needs network access and is off by default (`--online`).
- Normalise each match to `{cve, component, version, severity, cvss, fix_version, source}`.
- Summarise counts by severity, the top components by CVE count, and the CVEs in network-facing components.
- **Known-exploited flag:** optionally cross-reference the CISA KEV JSON (a local copy) to mark actively exploited CVEs.

Output: `vulns.json`.

### 6.5 `integrity.py`
- A SHA-256 manifest of the image and of every ELF plus key configuration files (`integrity_manifest.json`). This is the "digest manifest" that the supplier is later asked to sign.
- **Signature / verified-update indicators.** These are heuristics, and each one is reported as found or not found:
  - a detached signature next to the image (`--signature file.sig`), or `*.sig`, `*.asc` or `*.p7s` in the release
  - RAUC (`etc/rauc/system.conf` with a `[keyring]`), SWUpdate public keys, `opkg` `check_signature 1`
  - FIT-image signatures in U-Boot (`signature` nodes in `.itb`/DTB), dm-verity or IMA/EVM configuration
  - vendor update tools that verify signatures (e.g. strings such as `openssl dgst -verify` or `gpg --verify` in update scripts)
- Output: `integrity.json` with `{image_sha256, manifest_entries, signature_indicators[], verified_update_mechanism: present|absent|unknown}`.

### 6.6 `config_audit.py`
| Check | Where |
|-------|-------|
| Accounts with an empty password field or no password | `etc/shadow`, `etc/passwd` |
| Weak password hash algorithms (DES = 13 chars, MD5 = `$1$`) vs `$5$`/`$6$`/`$y$` | `etc/shadow` |
| Identical, documented default passwords | Compare the hashes against a small list of vendor defaults you supply (e.g. from public manuals) |
| Clear-text services enabled (telnetd, ftpd, tftpd, rsh, and HTTP without TLS) | `etc/inetd.conf`, `etc/init.d/*`, `etc/rc*.d/*`, systemd units, lighttpd/nginx configs |
| SSH: `PermitRootLogin`, `PasswordAuthentication`, weak ciphers | `etc/ssh/sshd_config`, `etc/dropbear/*` |
| **Embedded private keys**, e.g. SSH host keys or TLS keys identical on every device | Grep for `-----BEGIN (RSA\|EC\|OPENSSH\|) ?PRIVATE KEY-----` |

Output: `config.json`.

---

## 7. Normalized `evidence.json` (schema sketch)

```json
{
  "schema_version": "1.0",
  "target": { "name": "wago-fw13", "vendor": "WAGO", "product": "PFC200 750-8xxx",
              "version": "03.01.07(13)", "image_file": "WAGO_FW0750-8xxx_V030107_IX13_r40667.img",
              "image_sha256": "…", "collected_at": "2026-…", "specgen_version": "0.1.0",
              "tools": { "syft": "x.y.z", "grype": "x.y.z", "grype_db_built": "…" } },
  "hardening": {
    "executables": 412, "shared_libs": 380,
    "ratios": { "canary": 0.31, "nx": 0.98, "pie": 0.05, "relro_full": 0.02, "relro_partial": 0.90, "fortify": 0.22 },
    "network_daemons": [ { "path": "/usr/bin/iocheckd", "canary": false, "pie": false, "relro": "partial", "nx": true } ],
    "binaries_ref": "hardening.json"
  },
  "sbom": { "format": "CycloneDX-1.5", "components": 214, "with_version": 0.97, "with_cpe_or_purl": 0.91,
            "eol_components": [ { "name": "openssl", "version": "1.0.2p", "reason": "EOL 2019-12-31" } ],
            "ref": "sbom.cdx.json" },
  "vulns": { "critical": 12, "high": 57, "medium": 140, "low": 18, "kev": 3,
             "network_facing_critical_high": 9, "ref": "vulns.json" },
  "integrity": { "manifest_ref": "integrity_manifest.json", "verified_update_mechanism": "absent",
                 "signature_indicators": [] },
  "config": { "empty_password_accounts": [], "weak_hash_accounts": ["admin"],
              "cleartext_services": ["ftpd", "telnetd"], "ssh_root_login": true,
              "embedded_private_keys": ["/etc/dropbear/dropbear_rsa_host_key"] }
}
```
*(The numbers above are illustrative placeholders, not measured results.)*

A JSON Schema file (`schemas/evidence.schema.json`) validates every document before the rules run.

---

## 8. Mapping ruleset: the research core

### 8.1 Rule table

| ID | Category | Evidence | Metric / finding | Synthesized supplier requirement | IEC 62443 reference(s) |
|----|----------|----------|------------------|----------------------------------|------------------------|
| MS-01 | Memory safety | hardening | Stack-canary coverage in executables < 0.90 | Supplier shall compile all firmware user-space binaries with stack protection (`-fstack-protector-strong` or equivalent) and provide build-flag evidence. | 4-1 SI-2, SD-4; supports 4-2 CR 3.5 |
| MS-02 | Memory safety | hardening | Any network-facing daemon lacks a canary, PIE or full RELRO | Supplier shall harden all network-exposed services with canary + PIE + full RELRO + NX. | 4-1 SI-2, SD-4; 4-2 CR 3.5, CR 7.7 |
| MS-03 | Memory safety | hardening | NX coverage < 1.0 | Supplier shall ensure no executable stack segments ship in firmware. | 4-1 SD-4 |
| DH-01 | Dependency hygiene | sbom | SBOM missing, or < 90 % of components with a version or purl | Supplier shall deliver a machine-readable SBOM (CycloneDX or SPDX) with each release, covering ≥ 90 % of components with version and identifier. | 4-1 SM-9 (\*) |
| DH-02 | Dependency hygiene | vulns | Critical CVEs > 0, or KEV-listed CVEs > 0 | Supplier shall ship no known critical or actively exploited vulnerabilities in third-party components at delivery, or provide a VEX statement justifying non-exploitability. | 4-1 SM-9, DM-1…DM-6, SVV-3 |
| DH-03 | Dependency hygiene | vulns | High CVEs in network-facing components > N | Supplier shall remediate high-severity CVEs in network-facing components within an agreed SLA (e.g. 90 days). | 4-1 DM-4, DM-5, SUM-1…5 |
| DH-04 | Dependency hygiene | sbom | End-of-life components present (e.g. OpenSSL 1.0.x, an EOL kernel) | Supplier shall not ship components past upstream end-of-life without a documented support arrangement. | 4-1 SM-9 |
| CI-01 | Crypto integrity | integrity | No vendor-signed digest / signature for the image | Supplier shall provide a signed SHA-256 digest manifest for every firmware release before site commissioning. | 4-2 CR 3.4; 4-1 SUM-4 |
| CI-02 | Crypto integrity | integrity | No verified-update mechanism detected | Device shall verify the authenticity and integrity of firmware updates before installation. | 4-2 EDR 3.10, CR 3.4 |
| CI-03 | Crypto integrity | integrity | No boot-integrity indicators (signed FIT, dm-verity, secure boot) | Supplier shall document and enable boot-integrity protection. | 4-2 EDR 3.14 |
| SD-01 | Secure defaults | config | Clear-text services enabled by default | Clear-text management services (Telnet, FTP, TFTP, HTTP) shall be disabled by default. | 4-2 CR 7.7, CR 4.1; 4-1 SD-4 |
| SD-02 | Secure defaults | config | Empty, weak-hash or documented default passwords | Device shall force a change of default credentials at first use and store password hashes with a modern KDF. | 4-2 CR 1.5, CR 1.7 |
| SD-03 | Secure defaults | config | Private keys embedded in the image | Unique key material shall be generated per device at provisioning; no shared private keys shall be shipped in the firmware. | 4-2 CR 1.5, EDR 3.12/3.13 |

(\*) **Correctness note.** IEC 62443 clause texts are paywalled, and requirement IDs differ slightly between editions. Before you finalise, **verify every reference against your licensed copy** of IEC 62443-4-1:2018 and 62443-4-2:2019 and fix any that do not hold. Treat the items marked (\*) as "to be confirmed".

**Corrections to the original idea.** The initial sketch mapped "Stack Canaries = No" to *EDR 3.4* and CVE SLAs to *4-1 SR-2*. In 4-2, the 3.4 slot is **CR 3.4 Software and information integrity**, which belongs to the integrity category, not memory safety. In 4-1, **SR-2** is *threat model*. Memory-safety flags fit better under 4-1 **SI-2** (secure coding standards) and **SD-4** (secure design best practices). CVE handling fits better under **SM-9** (externally provided components) and the **DM** (defect management) practices.

### 8.2 Ruleset file format (`rules/ruleset.yaml`)

```yaml
version: 1
thresholds:            # defaults; can be overridden per project with --thresholds
  min_canary_ratio: 0.90
  min_nx_ratio: 1.0
  max_critical_cves: 0
  max_kev_cves: 0
  max_high_cves_network: 5
  min_sbom_identified_ratio: 0.90

rules:
  - id: MS-01
    category: memory_safety
    evidence: hardening.ratios.canary          # dotted path into evidence.json
    op: ">="
    threshold: min_canary_ratio
    severity: high
    requirement: >
      The supplier shall compile all firmware user-space binaries with stack
      protection (-fstack-protector-strong or equivalent) and provide build-flag
      evidence with each release.
    acceptance_test: "hardening.ratios.canary >= {min_canary_ratio}"
    iec62443: ["62443-4-1:SI-2", "62443-4-1:SD-4", "62443-4-2:CR 3.5"]
    rationale: >
      Stack canaries detect linear stack buffer overflows (the bug class in
      TALOS-2019-0862-type issues) and turn exploitation into a crash.

  - id: SD-03
    category: secure_defaults
    evidence: config.embedded_private_keys
    op: "empty"
    severity: critical
    requirement: >
      Unique key material shall be generated per device at provisioning. No
      private keys shall be shipped in the firmware image.
    iec62443: ["62443-4-2:CR 1.5", "62443-4-2:EDR 3.12"]
```

Operators supported by the rules engine: `>=`, `<=`, `==`, `empty`, `not_empty`, `in`, `all_true` (for per-daemon checks). Each evaluation produces:

```json
{ "rule_id": "MS-01", "status": "FAIL", "observed": 0.31, "expected": ">= 0.90",
  "evidence_ref": "/hardening/ratios/canary", "severity": "high" }
```

---

## 9. Outputs

### 9.1 `procurement_checklist.md` (excerpt, generated)

```markdown
# Supplier Security Requirements — PFC200 firmware
Derived from evidence of: WAGO FW 03.01.07(13)  (sha256 3f1c…)  |  ICS-SpecGen 0.1.0

## A. Memory-safety hardening
- [ ] **REQ-MS-01** The supplier shall compile all firmware user-space binaries with stack
      protection and provide build-flag evidence.  
      *Acceptance:* ≥ 90 % of executables carry stack canaries (observed: 31 %).  
      *Ref:* IEC 62443-4-1 SI-2, SD-4 · *Evidence:* hardening.json
...
## D. Secure defaults
- [ ] **REQ-SD-03** No private keys shall be shipped in the firmware image …
```

Each clause is written as a contractual "shall" statement with an **objective acceptance test**. This is what makes the checklist reusable in an RFP.

### 9.2 `gate_policy.rego` + `gate_data.json`

Rego v1 (OPA ≥ 1.0) syntax. The policy logic is generic, and `gate_data.json` carries the thresholds plus the metrics of the accepted baseline.

```rego
package icsspecgen.gate

# input = evidence.json of the candidate firmware
# data.icsspecgen = gate_data.json { thresholds, baseline }

default allow := false

allow if count(violations) == 0

t := data.icsspecgen.thresholds
b := data.icsspecgen.baseline

violations contains v if {
	input.hardening.ratios.canary < t.min_canary_ratio
	v := {"rule": "MS-01", "msg": sprintf("stack canary coverage %.2f < %.2f", [input.hardening.ratios.canary, t.min_canary_ratio])}
}

violations contains v if {
	some d in input.hardening.network_daemons
	not d.canary
	v := {"rule": "MS-02", "msg": sprintf("network daemon %s lacks stack canary", [d.path])}
}

violations contains v if {
	input.vulns.critical > t.max_critical_cves
	v := {"rule": "DH-02", "msg": sprintf("%d critical CVEs (max %d)", [input.vulns.critical, t.max_critical_cves])}
}

violations contains v if {
	input.integrity.verified_update_mechanism != "present"
	v := {"rule": "CI-02", "msg": "no verified-update mechanism detected"}
}

violations contains v if {
	count(input.config.embedded_private_keys) > 0
	v := {"rule": "SD-03", "msg": sprintf("embedded private keys: %v", [input.config.embedded_private_keys])}
}

# --- no-regression: a candidate update must not be worse than the accepted baseline
violations contains v if {
	some k in ["canary", "pie", "relro_full", "nx"]
	input.hardening.ratios[k] < b.hardening.ratios[k]
	v := {"rule": "REG-01", "msg": sprintf("regression in %s: %.2f < baseline %.2f", [k, input.hardening.ratios[k], b.hardening.ratios[k]])}
}

violations contains v if {
	input.vulns.critical > b.vulns.critical
	v := {"rule": "REG-02", "msg": "more critical CVEs than accepted baseline"}
}

decision := {"allow": allow, "violations": violations}
```

How an asset owner uses it during staging:

```powershell
# Gate a new firmware update candidate
python -m specgen collect .\candidate.img --name candidate --out .\out
opa eval -d .\policy\gate_policy.rego -d .\policy\gate_data.json `
         -i .\out\candidate\evidence.json "data.icsspecgen.gate.decision" --format pretty
# or wrapped:
python -m specgen gate .\out\candidate\evidence.json --policy .\policy
```

`specgen gate` exits with `0` when the firmware is allowed and `1` when it is denied, so it can sit in any CI or staging script.

### 9.3 `acceptance_report.md`
1. Target identity table: vendor, version, SHA-256 and tool versions
2. Summary scorecard: pass/fail per category for each firmware, side by side
3. Hardening ratios table, plus a list of network-facing daemons with their flags
4. CVE summary by severity, the top 10 components and KEV hits
5. Integrity and secure-defaults findings
6. Gate decision for each firmware, and the regression test result (FW13 evaluated against the FW24 baseline)
7. Traceability matrix: rule → evidence → IEC 62443 reference → requirement

---

## 10. Repository layout

```
ICS-SpecGen/
├── PROJECT.md                 ← this document
├── README.md                  quick start
├── requirements.txt           pyelftools, PyYAML, Jinja2, jsonschema
├── specgen/
│   ├── __main__.py            enables `python -m specgen`
│   ├── cli.py                 argparse: doctor | collect | evaluate | generate | run | gate
│   ├── tools.py               locate 7z/syft/grype/opa, run subprocesses, capture versions
│   ├── unpack.py
│   ├── hardening.py
│   ├── sbom.py                syft wrapper + opkg/dpkg parser + version carving + merge
│   ├── vulns.py               grype wrapper + OSV fallback + KEV tagging
│   ├── integrity.py
│   ├── config_audit.py
│   ├── evidence.py            assemble + validate evidence.json
│   ├── rules.py               ruleset loader + evaluator
│   └── render.py              Jinja2 → md / rego / json
├── rules/ruleset.yaml
├── schemas/evidence.schema.json
├── templates/
│   ├── procurement_checklist.md.j2
│   ├── acceptance_report.md.j2
│   └── gate_policy.rego.j2
├── policy/                    generated gate_policy.rego, gate_data.json, gate_policy_test.rego
├── tools/bin/                 (git-ignored) 7z.exe, syft.exe, grype.exe, opa.exe
├── firmware/                  (git-ignored) downloaded images
├── work/                      (git-ignored) extraction scratch
├── out/<name>/                evidence.json, hardening.json, sbom.cdx.json, vulns.json, …
└── tests/
    ├── fixtures/              synthetic evidence.json files, tiny ELF samples
    ├── test_hardening.py
    ├── test_sbom_opkg.py
    ├── test_rules.py
    └── test_render.py
```

CLI summary:

| Command | Does |
|---------|------|
| `specgen doctor` | Report the tools found on PATH or in `tools/bin`, and which fallbacks are active |
| `specgen collect <image> --name N --out out/` | Unpack and run all evidence modules → `out/N/evidence.json` |
| `specgen evaluate out/N/evidence.json` | Apply the ruleset → `findings.json` |
| `specgen generate --targets out/A out/B --baseline B` | Write the checklist, the Rego policy and data, and the report |
| `specgen run <img1> <img2> --baseline <name>` | All of the above, end to end |
| `specgen gate <evidence.json> --policy policy/` | Call `opa eval`; exit code 0 = allow, 1 = deny |

---

## 11. Implementation phases

| Phase | Work | Exit criterion |
|-------|------|----------------|
| **P0 Setup** | Install the tools (§5), create the repository skeleton, `specgen doctor`, download the FW13 and FW24 images, and record their SHA-256 | `doctor` shows all green |
| **P1 Unpack + hardening** | `unpack.py`, `hardening.py`, tests on small ELF fixtures | The rootfs of both WAGO images is extracted, and `hardening.json` is produced |
| **P2 SBOM + CVEs** | syft wrapper, opkg parser, version carving, CPE/purl generation, grype wrapper | `sbom.cdx.json` and `vulns.json` exist for both images, and the opkg-derived components are matched by grype |
| **P3 Integrity + config** | `integrity.py`, `config_audit.py` | Findings exist for both images |
| **P4 Ruleset + engine** | `ruleset.yaml` (13 rules), JSON schema, `rules.py` | `findings.json` exists for both images; unit tests cover every operator |
| **P5 Generators** | Jinja2 templates, Rego generation, `gate_policy_test.rego` | `opa check` and `opa test` pass; the checklist renders |
| **P6 Evaluation + write-up** | Run §12, cross-validate (§13), write the report and your analysis | Hypotheses answered with numbers |

The critical path is P1 → P2, since unpacking and SBOM quality drive everything else. Start with the FW13 image because it is smaller.

---

## 12. Evaluation methodology

**Setup.**
- FW13 is the *candidate/insecure* firmware; FW24 (or FW22) is the *accepted baseline*.
- Optionally run the RevPi Buster → Trixie pair as a generalisation check.

**Hypotheses**

| # | Hypothesis | Measured by |
|---|-----------|-------------|
| H1 | The newer firmware has higher hardening coverage (canary, PIE, full RELRO) | `hardening.ratios` for FW13 vs FW24; per-daemon flags for `iocheckd`, the web server and the CODESYS runtime |
| H2 | The older firmware carries more critical/high and KEV-listed CVEs | `vulns` counts |
| H3 | The ruleset flags known weaknesses: the Talos iocheckd CVEs fall inside components the rules flag | Manual trace: TALOS-2019-0862/0872 → `iocheckd` → MS-02 / DH-02 findings |
| H4 | The generated gate **denies** FW13 and **allows** FW24, or shows strictly fewer violations | `specgen gate` exit code and the violation list |
| H5 | The no-regression rule blocks a **downgrade**: FW13 is rejected against the FW24 baseline even if absolute thresholds were loosened | Rerun the gate with relaxed thresholds; the REG-* violations must remain |

**Metrics to report**
- Number of evidence items per category
- Rules triggered per firmware
- Coverage: the share of the 13 rules that could be evaluated (not N/A)
- Pipeline runtime per image
- SBOM identification ratio with and without the opkg fallback. This shows what the custom parser contributes.

---

## 13. Validation and testing

- **Unit tests (pytest)**
  - hardening detection on fixture ELFs (known canary / no canary, PIE / non-PIE)
  - opkg status parsing
  - rule operators
  - template rendering
- **Policy tests.** Generate `policy/gate_policy_test.rego` with a passing and a failing synthetic input. It must pass `opa test policy/ -v` and `opa check --strict`.
- **Cross-tool agreement**
  - Run `checksec.py` (LIEF-based) on a random sample of 30 ELFs from each image and report the agreement % with `hardening.py` for each property.
  - Investigate any disagreement. ARM canary detection through `__stack_chk_guard` is the usual cause.
- **SBOM sanity.** Spot-check 10 components against the package versions in the WAGO release notes PDF.
- **Ground truth.** Confirm that `iocheckd` exists in the FW13 rootfs and appears among the network-facing daemons.
- **Reproducibility**
  - Record the tool versions and the grype DB build date in `evidence.json`.
  - Running twice must give identical `evidence.json`, apart from timestamps.

---

## 14. Risks and limitations

| Risk | Mitigation |
|------|------------|
| 7-Zip cannot parse a partition type (e.g. UBIFS or JFFS2 on NAND images) | The WAGO SD `.img` files are block-device images, so this is not expected. Otherwise add `ubi_reader` or `jefferson` (pure Python) as optional unpackers. |
| Symlinks and case collisions on NTFS | See §5. The analysis ignores symlinks and records them. |
| syft does not catalogue opkg/ipkg packages | Custom opkg parser plus CPE generation (§6.3) |
| CPE mismatches cause false positive or negative CVE matches | Report the match confidence; allow a `cpe_overrides.yaml`; list unmatched components separately |
| Proprietary components (CODESYS runtime, WAGO daemons) have no CVE mapping in grype | Carve version strings; list vendor advisories (CERT@VDE, Talos) manually in a small `known_advisories.yaml` |
| Signature detection is heuristic | Report it as an *indicator*, never as proof; the requirement asks the supplier for evidence |
| IEC 62443 text is paywalled, so reference IDs could be wrong | §8.1 correctness note: verify against a licensed copy before publishing |
| Comparing different hardware generations (FW13 8xxx vs FW24 G2) | Use FW22 8x1x as the baseline, or state the confounder explicitly |
| Legal: redistributing vendor firmware | Don't commit the images. Store the SHA-256 and the download URL only. |

---

## 15. Stretch goals

1. **Bare-metal profile (the ESP32-PLC in this folder).**
   - Build `ESP32-PLC` with ESP-IDF to get the `.elf`.
   - Use `sdkconfig` and the image header as evidence. Linux-only checks (PIE, RELRO) are marked **N/A**.
   - The current `sdkconfig` already shows useful findings:
     - `CONFIG_SECURE_BOOT` not set → CI-03
     - `CONFIG_SECURE_FLASH_ENC_ENABLED` not set
     - `CONFIG_COMPILER_STACK_CHECK_MODE_NONE=y` → MS-01
     - the FTP server component → SD-01
   - Pinned dependencies in `main/idf_component.yml` feed the SBOM.
2. **Vendor update containers.** Unpack the WAGO `.wup` format, and parse the signature section of Phoenix PLCnext `.raucb` bundles. That would give a positive CI-02 example.
3. **VEX input.** Accept supplier CycloneDX VEX so that CVEs marked `not_affected` do not trigger DH-02.
4. **SARIF output**, so the findings show up in GitHub code scanning.
5. **Longitudinal study** across WAGO FW16 → FW24, charting how the hardening ratios and CVE counts evolve.

---

## 16. References

**Firmware sources**
- WAGO PFC firmware releases: https://github.com/WAGO/pfc-firmware/releases
- Revolution Pi downloads: https://revolutionpi.com/en/support/downloads · Buster archive: https://packages.revolutionpi.com/buster/
- Phoenix Contact AXC F 2152: https://www.phoenixcontact.com/en-us/products/controller-axc-f-2152-2404267

**Vulnerabilities (ground truth for FW13)**
- Talos, *Multiple vulnerabilities in WAGO PFC200*: https://blog.talosintelligence.com/vulnerability-spotlight-multiple-63063210e63ef5e7e1ec312e/
- TALOS-2019-0862 (CVE-2019-5073): https://talosintelligence.com/vulnerability_reports/TALOS-2019-0862
- TALOS-2019-0872: https://talosintelligence.com/vulnerability_reports/TALOS-2019-0872
- CISA Known Exploited Vulnerabilities catalogue: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Tools and formats**
- Syft: https://github.com/anchore/syft · Grype: https://github.com/anchore/grype
- Open Policy Agent / Rego: https://www.openpolicyagent.org/docs/latest/policy-language/
- CycloneDX specification: https://cyclonedx.org/specification/overview/
- pyelftools: https://github.com/eliben/pyelftools · checksec.py: https://github.com/Wenzel/checksec.py
- 7-Zip: https://www.7-zip.org/ · OSV API: https://google.github.io/osv.dev/api/

**Standards**
- ISA/IEC 62443 series overview: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- IEC 62443-4-1:2018, *Secure product development lifecycle requirements*
- IEC 62443-4-2:2019, *Technical security requirements for IACS components*

**Related research**
- *Bridging the PLC Binary Analysis Gap* (PLC-BEAD dataset): https://arxiv.org/pdf/2502.19725
- Nozomi Networks, *PLC Firmware Extraction Through Native Code Execution*: https://www.nozominetworks.com/blog/plc-firmware-extraction-through-native-code-execution
