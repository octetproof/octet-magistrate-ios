# Changelog

Changes to Magistrate for iOS that affect your integration. Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

The first public release of Magistrate for iOS.

- `Magistrate(sdk).decide(license:)` and `decideMany(license:)` answer a policy
  question for the device with YES, NO or UNKNOWN. An UNKNOWN answer carries a
  `cause`.
- `prove(license:nonce:)`, `attestationEnrolment()` and `challengeEnv(license:)` let
  your server start the check and send the decide itself.
- Every answer comes with a signed receipt that your server can verify. See
  INTEGRATION.md.
- Each release's `SHASUMS256.txt` is signed with Sigstore by this repository's
  `sign-release.yml` (bundle `SHASUMS256.txt.sigstore.json`). README.md shows how to
  verify a download.
- `SECURITY.md`: how to report a vulnerability.
- When the policy bundle can't be refreshed, Magistrate falls back to the last one it
  verified, but only for the same bundle URL and only while that bundle still verifies
  against your licence's current keys.
- Builds signed in with a sandbox token run sandbox checks; their receipts say
  `env: "sandbox"`. Production receipts say `env: "release"`.
- Requires `octet-sdk-ios` 3.1.2, pinned exactly (see README.md), and iOS 16 or
  later.
