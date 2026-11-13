# Security

## Reporting a vulnerability

Report a suspected vulnerability privately to **security@octetproof.com**. That
includes a decision or receipt that verifies when it should not, a policy bundle that
Magistrate accepts although it is not validly signed, a cached bundle used after it
stopped verifying, and any flaw in how the library handles keys, proofs or receipts.
Include the Magistrate and OctetSDK versions, the platform and OS version, the
`decisionRef` of an affected check if you have one, and the smallest steps that show
the problem. Do not open a public issue for a verification bypass until it has been
triaged.

## What the release signature covers

The `cosign` check in the README confirms that `SHASUMS256.txt` was signed by this
repository's `sign-release.yml` workflow for exactly that release tag. The checksum
check then confirms that each release file is the one listed in that signed file.

The release files are not reproducible builds. The signature and the checksums are
how you check them.

## What a decision establishes

The app's copy of a decision is only as trustworthy as the device it runs on. Forward
the signed `receipt` to your backend and check it there, as described in
`INTEGRATION.md` (Verifying the receipt on your server), before you act on it.
