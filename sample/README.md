# Magistrate sample — iOS (public)

A minimal SwiftUI app that runs the one-call attested policy decision:
`Octet.start` → `Magistrate(sdk).decide(license)` → Permit / Deny. Bundle id
**`com.octetproof.magistrate`**. Mirrored to `octet-magistrate-ios` (`main/sample`) on
each release.

Tap **Decide** and the app starts OctetSDK, lets the location pipeline warm up, then
calls `Magistrate.decide` and shows the decision, reasons, obligations, and
`decisionRef`.

## Run

1. Register the app on your Octet license. OctetSDK signs in with App Attest, so
   there's no key to paste: the sample starts it with `OctetConfig()`.
2. `brew install xcodegen && xcodegen generate && open MagistrateSample.xcodeproj`
3. Run on a **real device** (the decision needs an attested on-device location proof;
   grant location + motion when prompted).

See [`INTEGRATION.md`](../INTEGRATION.md) for the
full API.
