# CEPS C2PA Generator Security Review — 2026-11-03

> Status: evidence and triage register. This document does not claim that all findings are exploitable in every deployment, that remediation is complete, or that the product meets GPSA Assurance Level 1.

## 1. Review scope

This review covers the CEPS C2PA Generator dependency inventory, selected C2PA Rust SDK archive-reading paths, the live PHP Generator upload boundary, and the separation between technical C2PA validation and signer/timestamp trust.

## 2. Inventory evidence

- CycloneDX 1.5 Rust SBOM: 557 resolved Cargo packages plus the root workspace component; 558 component/dependency references; structural reference validation passed.
- OSV-Scanner 2.7.0 recognised 557 packages in the SBOM.
- The scan reported 16 unique advisory IDs across six package names: `zip`, `quinn-proto`, `crypto-bigint`, `rustls-webpki`, `rsa`, and `proc-macro-error`.
- The separate QR PHP Composer project contains two locked packages; `composer audit --locked` reported no advisories for those two packages only. This is not a full runtime/OS scan.
- A complete NVD scan and full OS/runtime SCA are not yet evidenced.

## 3. Dependency advisory triage

### 3.1 `zip 8.6.0` — open for dependency and SDK-path review

OSV reported:
- `RUSTSEC-2026-0367`
- `RUSTSEC-2026-0368`
- `RUSTSEC-2026-0369`
- `RUSTSEC-2026-0429`
- `GHSA-8hxf-qr8p-62x4`
- `GHSA-9hj8-73fh-9963`
- `GHSA-hjqx-j4rw-g7xv`
- `GHSA-m665-v7pm-7grj`
- `GHSA-q7v9-x93c-xqv3`

Code-path observations in the inspected SDK workspace:
- `Builder::with_archive()` calls the legacy `old_from_archive()` first.
- The legacy loader reads `manifest.json`, resource entries, manifest entries and ingredient entries using `read_to_end()` into `Vec` values. No explicit size limit was visible in the inspected code. Path sanitisation is present, but it is not a decompression or aggregate-memory limit.
- `ZipIO::read_cai()` reads the C2PA manifest entry using `read_to_end()` into a `Vec`; no explicit size cap was visible in that function.
- `ZipIO` is registered in the SDK's central JUMBF handler list.
- No direct ZIP `.extract()` call was identified in the inspected C2PA paths. Extraction-specific advisories require separate applicability analysis; parser/decoder advisories remain open.

Production reachability qualification:
- The live CEPS PHP Generator accepts only JPEG, PNG, GIF and WebP for both source and ingredient inputs.
- The endpoint checks uploaded MIME type with PHP `finfo` and enforces a 25 MiB maximum upload size.
- ZIP-based document inputs are not accepted by this endpoint. The inspected ZIP SDK findings are therefore **not demonstrated as reachable through the live Generator's normal upload interface**. They remain SDK hardening concerns and must not be described as confirmed production exploitation.

### 3.2 `rustls-webpki 0.103.15` — high-priority certificate-validation review

OSV reported `RUSTSEC-2026-0382` (certificate verification may accept distrusted intermediates). Confirm affected target/features, upstream fixed version and compatible Rustls update before changing the lockfile.

### 3.3 `crypto-bigint 0.5.5` — cryptographic timing review

OSV reported `RUSTSEC-2026-0387`. Assess affected constant-time operations and upstream fixed release/compatibility before upgrading.

### 3.4 `rsa 0.9.10` — cryptographic timing review

OSV reported `RUSTSEC-2023-0071` (Marvin timing side-channel). Trace actual C2PA RSA operation paths and assess whether the deployed build exposes affected operations.

### 3.5 `quinn-proto 0.11.17` — target/feature applicability unresolved

OSV reported:
- `RUSTSEC-2026-0338`
- `RUSTSEC-2026-0340`
- `RUSTSEC-2026-0343`

The default `cargo tree -i` query did not show a path. Re-run with all targets/features and establish whether this package is included in the deployed target.

### 3.6 `proc-macro-error 1.0.4` — maintenance warning

OSV reported `RUSTSEC-2024-0370` (unmaintained). Trace the parent dependency and replace only through a compatible upstream update.

## 4. Verified safeguards and limitations

- The SDK default `core.max_decompressed_manifest_size_in_mb` is 32 MB and is applied in the JUMBF decompression path. This does not bound the legacy ZIP entry reads described above.
- The live Generator's four-format upload allowlist, MIME check and 25 MiB cap are verified from the current PHP endpoint and configuration.
- The live JPEG validation showed a valid signature and data hash. The active CEPS signing credential remains untrusted; the FreeTSA timestamp digest validated, but the timestamp certificate remains untrusted. Timestamp digest validation is not equivalent to TSA certificate trust.
- The PHP Composer audit result covers only the two locked packages in the separate QR helper project.
- The OSV scan is one advisory-database scan of the Rust SBOM. It is not a complete NVD scan, runtime/OS SCA, exploitability assessment or security certification.

## 5. Required next actions

1. Confirm upstream fixed versions and target/feature applicability for each OSV finding.
2. Prioritise `rustls-webpki` and `crypto-bigint`; inspect RSA operation reachability.
3. Evaluate the ZIP crate upgrade and add bounded reads, entry-count limits and aggregate archive limits to SDK paths where appropriate, with regression tests for oversized and decompression-bomb archives.
4. Complete NVD and runtime/OS inventory, including ImageMagick, PHP/GD/Imagick, OS packages and signer/runtime components.
5. Rebuild from a reviewed lockfile, rerun OSV and other SCA, run functional C2PA tests for JPEG/PNG/GIF/WebP, and retain reports.
6. Keep the production Generator unchanged until a candidate build has passed testing and has been explicitly approved for deployment.

## 6. Assurance statement

This review does not establish GPSA Assurance Level 1, production signer trust, C2PA certification, or a clean security posture. The GPSA review's overall verdict remains **DOES NOT MEET** until all applicable requirements are evidenced and independently reviewed.
