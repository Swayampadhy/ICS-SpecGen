# ICS-SpecGen

**Evidence-driven supply-chain requirements for PLC firmware.**

ICS-SpecGen statically analyses a Linux-based PLC firmware image (`.img`, `.zip`, `.7z`) and turns what it finds into supplier requirements mapped to IEC 62443. It produces a procurement checklist, an executable OPA/Rego acceptance gate and a report that compares firmware versions. It runs natively on Windows, with no Docker, WSL or VM required.

## Features

- **ELF hardening:** checks stack canaries, NX, PIE, RELRO and FORTIFY per binary, and separately for network-facing daemons.
- **SBOM and CVEs:** builds a CycloneDX SBOM (syft, opkg/dpkg, license files, version carving), matches it with grype and tags CISA KEV entries.
- **Integrity:** writes a SHA-256 manifest and looks for signed-update and boot-integrity indicators (RAUC, SWUpdate, FIT, dm-verity, IMA).
- **Secure defaults:** flags default or weak passwords, clear-text services, SSH settings and private keys shipped in the image.
- **13-rule YAML ruleset:** every finding cites its rule, its evidence and the IEC 62443 clause.
- **OPA gate:** includes no-regression rules against an accepted baseline.

## Requirements

- Windows 10/11 (x64) and Python 3.10 or later
- [7-Zip](https://www.7-zip.org/), [syft](https://github.com/anchore/syft/releases), [grype](https://github.com/anchore/grype/releases) and [OPA](https://github.com/open-policy-agent/opa/releases), either on `PATH` or in `tools\bin\`

## Install

```powershell
git clone https://github.com/Swayampadhy/ICS-SpecGen.git
cd ICS-SpecGen
pip install -r requirements.txt
winget install 7zip.7zip
# copy syft.exe, grype.exe and opa.exe into tools\bin\
.\tools\bin\grype.exe db update
curl.exe -L -o tools\kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
python -m specgen doctor
```

## Usage

```powershell
# Analyse two versions and compare them against an accepted baseline
python -m specgen run firmware\old.img firmware\new.img --names old new --baseline new --work C:\sg\work

# Gate one firmware: exit code 0 = allow, 1 = deny
python -m specgen gate out\old\evidence.json --policy policy
```

| Command | Purpose |
|---|---|
| `doctor` | Check tools, the grype database and Python packages |
| `collect <image> --name N` | Unpack the image and write `out\N\evidence.json` |
| `evaluate <evidence.json>` | Apply the ruleset and write `findings.json` |
| `generate --targets out\A out\B --baseline B` | Write the checklists, gate data and report |
| `run <images...> --names ... --baseline N` | Run collect, evaluate and generate in one go |
| `gate <evidence.json> --policy policy` | Evaluate the OPA gate |

Common options: `--out`, `--work`, `--thresholds <yaml>`, `--vendor`, `--product` and `--kev`. Use `collect --signature <file>` to supply a detached vendor signature for the image.

## Outputs

| File | Contents |
|---|---|
| `out\<name>\evidence.json`, `findings.json` | Normalized evidence and the PASS/FAIL/N/A result of each rule |
| `out\<name>\procurement_checklist.md` | Supplier "shall" clauses, each with an acceptance test |
| `out\acceptance_report.md` | Side-by-side comparison, gate decisions and a traceability matrix |
| `policy\gate_policy.rego`, `policy\gate_data.json` | The acceptance gate and its rules, thresholds and baseline |

## Customising

Override thresholds with `--thresholds my_thresholds.yaml` (see `rules\relaxed_thresholds.yaml`). You can add or edit rules in `rules\ruleset.yaml`, and the gate picks them up the next time you run `generate`.

## Notes

- Keep `--work` on a short path outside synced folders, and exclude it from antivirus scanning if extracted files get quarantined.
- Every check is static, and some are heuristics. Treat findings as evidence for a supplier conversation, not as proof.
- Verify the IEC 62443 references against your licensed copy of the standard.
- Don't redistribute vendor firmware. `firmware\` and `tools\bin\` are git-ignored.

## Development

```powershell
python -m pytest tests -q
.\tools\bin\opa.exe test policy -v
```

## License

MIT. See [LICENSE](LICENSE).
