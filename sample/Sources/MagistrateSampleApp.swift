import SwiftUI
import OctetSDK
import Magistrate

// Magistrate sample (iOS) — the one-call attested policy decision:
//   Octet.start  →  Magistrate(sdk).decide(license)  →  Permit / Deny.
// decide() runs the whole exchange in one call: fetch + verify the policy bundle,
// request a single-use challenge, prove the required regions bound to that challenge,
// submit, and return the decision. A deny is a returned result, not an error.
//
// Register this app on your Octet license; OctetSDK 3.x signs in with App Attest, so
// there's no key to paste.

@main
struct MagistrateSampleApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @State private var lines: [String] = ["Tap to run the policy decision (Magistrate.decide)."]
    @State private var running = false
    @State private var sdk: OctetSdk?

    var body: some View {
        VStack(spacing: 12) {
            Button(running ? "Running…" : "Decide (Magistrate.decide)") {
                Task { await run() }
            }
            .disabled(running).buttonStyle(.borderedProminent)
            ScrollView {
                Text(lines.joined(separator: "\n"))
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading).padding()
            }
        }.padding()
    }

    private func log(_ s: String) { lines.append(s) }

    private func run() async {
        running = true; defer { running = false }
        do {
            log("\n① Starting OctetSDK…")
            let s: OctetSdk
            if let existing = sdk { s = existing } else {
                s = try await Octet.start(
                    // No licence key: OctetSDK signs in with App Attest (or a sandbox token).
                    config: OctetConfig(),
                    startPosition: nil
                )
                sdk = s
            }
            guard let license = s.licenseStatus else {
                log("   ✗ no licenseStatus — activation didn't complete."); return
            }
            log("   ✓ activated")

            // decide() needs the SDK's location pipeline warm enough to mint a fresh
            // proof. Give it a moment to settle after start, then retry a few times.
            log("② letting the location pipeline warm up…")
            try? await Task.sleep(nanoseconds: 12_000_000_000)

            for attempt in 1...6 {
                do {
                    log("③ decide() attempt \(attempt)…")
                    let r = try await Magistrate(sdk: s).decide(license: license)
                    log("   \(r.isPermit ? "✓ PERMIT" : "✗ DENY")  (decision=\(r.decision))")
                    if !r.reasons.isEmpty { log("   reasons: \(r.reasons.joined(separator: "; "))") }
                    if !r.obligations.isEmpty { log("   obligations: \(r.obligations)") }
                    log("   decisionRef=\(r.decisionRef)")
                    return
                } catch {
                    log("   [\(attempt)] \(error)")
                    if attempt < 6 { try? await Task.sleep(nanoseconds: 15_000_000_000) }
                }
            }
            log("✗ couldn't produce a decision — check location permission and network.")
        } catch {
            // e.g. PolicyError.notProvisioned / .licenseIdUnavailable / .decideRejected(…)
            log("   ✗ \(error)")
        }
    }
}
