# Supplier Security Requirements — PFC100/PFC200 firmware

Derived from evidence of: WAGO FW 03.01.07(13) (`WAGO_FW0750-8xxx_V030107_IX13_r40667.img`, sha256 `0f18326a6f5d56a7…`) | ICS-SpecGen 0.1.0

Each clause is a contractual "shall" statement with an objective acceptance test. A ticked box means this
firmware already meets the clause; an open box means the evidence triggered it (or it could not be evaluated).

## A. Memory-safety hardening

- [ ] **REQ-MS-01** The supplier shall compile all firmware user-space binaries with stack protection (-fstack-protector-strong or equivalent) and provide build-flag evidence with each release.
  - *Acceptance:* at least 90% of executables carry stack canaries.
  - *Observed:* `/hardening/ratios/canary` = 0.0365 (FAIL)
  - *Ref:* IEC 62443-4-1:SI-2, 62443-4-1:SD-4, 62443-4-2:CR 3.5 · *Severity:* high · *Status:* **FAIL**
- [ ] **REQ-MS-02** The supplier shall harden all network-exposed services with stack canaries, PIE, full RELRO and NX.
  - *Acceptance:* every network-facing daemon has canary, PIE, full RELRO and NX.
  - *Observed:* `/hardening/network_daemons` = /etc/config-tools/config_mdmd, /usr/bin/busybox, /usr/bin/codesys3, /usr/bin/dataagent, /usr/bin/dbus-daemon, /usr/bin/drm, /usr/bin/eactingbox, /usr/bin/iocheckd (+15 more) (FAIL)
  - *Ref:* IEC 62443-4-1:SI-2, 62443-4-1:SD-4, 62443-4-2:CR 3.5, 62443-4-2:CR 7.7 · *Severity:* critical · *Status:* **FAIL**
- [ ] **REQ-MS-03** The supplier shall ensure that no executable stack segments ship in the firmware.
  - *Acceptance:* 100% of executables have a non-executable stack.
  - *Observed:* `/hardening/ratios/nx` = 0.9967 (FAIL)
  - *Ref:* IEC 62443-4-1:SD-4 · *Severity:* high · *Status:* **FAIL**

## B. Dependency hygiene

- [x] **REQ-DH-01** The supplier shall deliver a machine-readable SBOM (CycloneDX or SPDX) with each release, covering at least 90 % of components with version and identifier (purl or CPE).
  - *Acceptance:* at least 90% of SBOM components have a version and a purl/CPE.
  - *Observed:* `/sbom/identified` = 0.9963 (PASS)
  - *Ref:* IEC 62443-4-1:SM-9 · *Severity:* medium · *Status:* **PASS**
- [ ] **REQ-DH-02** The supplier shall ship no known critical or actively exploited vulnerabilities in third-party components at delivery, or provide a VEX statement justifying non-exploitability.
  - *Acceptance:* no more than 0 critical and 0 KEV-listed CVEs.
  - *Observed:* `/vulns/critical` = 153 (FAIL); `/vulns/kev` = 16 (FAIL)
  - *Ref:* IEC 62443-4-1:SM-9, 62443-4-1:DM-1..DM-6, 62443-4-1:SVV-3 · *Severity:* critical · *Status:* **FAIL**
- [ ] **REQ-DH-03** The supplier shall remediate high-severity CVEs in network-facing components within an agreed SLA (e.g. 90 days).
  - *Acceptance:* no more than 5 critical/high CVEs in network-facing components.
  - *Observed:* `/vulns/network_facing_critical_high` = 236 (FAIL)
  - *Ref:* IEC 62443-4-1:DM-4, 62443-4-1:DM-5, 62443-4-1:SUM-1..SUM-5 · *Severity:* high · *Status:* **FAIL**
- [ ] **REQ-DH-04** The supplier shall not ship components past upstream end-of-life without a documented support arrangement.
  - *Acceptance:* no end-of-life components (e.g. OpenSSL 1.x, pre-5.10 kernels).
  - *Observed:* `/sbom/eol_components` = {'name': 'linux', 'version': '4.9.115-rt93', 'reason': 'Linux kernels before 5.10 are past upstream end of life'}, {'name': 'openssl', 'version': '1.0.2q', 'reason': 'OpenSSL 1.x is past end of life (1.1.1 ended 2023-09-11)'} (FAIL)
  - *Ref:* IEC 62443-4-1:SM-9 · *Severity:* high · *Status:* **FAIL**

## C. Cryptographic integrity

- [ ] **REQ-CI-01** The supplier shall provide a signed SHA-256 digest manifest for every firmware release before site commissioning.
  - *Acceptance:* a vendor signature or signed digest accompanies the image.
  - *Observed:* `/integrity/image_signature` = absent (FAIL)
  - *Ref:* IEC 62443-4-2:CR 3.4, 62443-4-1:SUM-4 · *Severity:* high · *Status:* **FAIL**
- [x] **REQ-CI-02** The device shall verify the authenticity and integrity of firmware updates before installation.
  - *Acceptance:* a signature-verifying update mechanism is present (e.g. RAUC keyring).
  - *Observed:* `/integrity/verified_update_mechanism` = present (PASS)
  - *Ref:* IEC 62443-4-2:EDR 3.10, 62443-4-2:CR 3.4 · *Severity:* critical · *Status:* **PASS**
- [ ] **REQ-CI-03** The supplier shall document and enable boot-integrity protection (signed FIT, dm-verity or secure boot).
  - *Acceptance:* boot-integrity indicators are present.
  - *Observed:* `/integrity/boot_integrity` = absent (FAIL)
  - *Ref:* IEC 62443-4-2:EDR 3.14 · *Severity:* medium · *Status:* **FAIL**

## D. Secure defaults

- [x] **REQ-SD-01** Clear-text management services (Telnet, FTP, TFTP, rsh, HTTP) shall be disabled by default.
  - *Acceptance:* no clear-text services enabled by default.
  - *Observed:* `/config/cleartext_services` = none (PASS)
  - *Ref:* IEC 62443-4-2:CR 7.7, 62443-4-2:CR 4.1, 62443-4-1:SD-4 · *Severity:* high · *Status:* **PASS**
- [ ] **REQ-SD-02** The device shall force a change of default credentials at first use and store password hashes with a modern KDF.
  - *Acceptance:* no empty, weakly hashed or documented default passwords.
  - *Observed:* `/config/empty_password_accounts` = none (PASS); `/config/weak_hash_accounts` = none (PASS); `/config/default_password_accounts` = admin, root, user (FAIL)
  - *Ref:* IEC 62443-4-2:CR 1.5, 62443-4-2:CR 1.7 · *Severity:* critical · *Status:* **FAIL**
- [ ] **REQ-SD-03** Unique key material shall be generated per device at provisioning; no private keys shall be shipped in the firmware image.
  - *Acceptance:* no private keys in the image.
  - *Observed:* `/config/embedded_private_keys` = /etc/dropbear/dropbear_dss_host_key, /etc/dropbear/dropbear_ecdsa_host_key, /etc/dropbear/dropbear_rsa_host_key, /etc/lighttpd/https-cert.pem (FAIL)
  - *Ref:* IEC 62443-4-2:CR 1.5, 62443-4-2:EDR 3.12 · *Severity:* critical · *Status:* **FAIL**

