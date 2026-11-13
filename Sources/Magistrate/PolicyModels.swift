// Sources/Magistrate/PolicyModels.swift
// Public result + error types for the Magistrate facade.
//
// These deliberately do NOT expose the Rust core's types: its generated bindings
// are compiled into this module as `internal` (see scripts/gen-magistrate-bindings.sh),
// so a consumer imports only OctetSDK + Magistrate and the core's wire types can
// evolve without breaking Magistrate's public surface.

import Foundation
@_spi(OctetModules) import OctetSDK

/// The verdict for one region a verified bundle requires the device to prove.
public struct PolicyRegionResult: Sendable {
    /// The bundle's canonical region string, verbatim from the signed bundle
    /// (e.g. `"country:US"`, `"subdivision:US-CA"`). Use it to correlate this
    /// result back to the policy that required it.
    public let canonical: String

    /// The base-SDK region the predicate was evaluated against, mapped from the
    /// bundle's region spec.
    public let region: OctetRegion

    /// The location verdict from `loc.isWithin(region:decisionRef:)` — the same
    /// decision-bound proof any host would mint for this region.
    public let verdict: OctetVerdict

    public init(canonical: String, region: OctetRegion, verdict: OctetVerdict) {
        self.canonical = canonical
        self.region = region
        self.verdict = verdict
    }
}

/// The outcome of `Magistrate.evaluate`: one `PolicyRegionResult` per region the
/// verified bundle requires. The bundle backing this evaluation is always trusted
/// (`VALID` when freshly fetched, or a previously-`VALID` cached bundle) — an
/// untrusted bundle with no trusted fallback throws before any region is
/// evaluated (fail-closed).
public struct PolicyEvaluation: Sendable {
    public let regions: [PolicyRegionResult]

    /// `true` when the fresh fetch/verify failed and evaluation fell back to the
    /// last-known-`VALID` cached bundle. The regions are still trusted, but the
    /// policy may be stale — a host can surface this or force a retry.
    public let servedFromCache: Bool

    public init(regions: [PolicyRegionResult], servedFromCache: Bool = false) {
        self.regions = regions
        self.servedFromCache = servedFromCache
    }
}

/// A persisted policy-bundle record: the last-known-`VALID` bundle JSON, its
/// monotonic version (the downgrade anchor), and the bundle URL it was fetched
/// from. Magistrate uses a record only for that same URL, and only while its bundle
/// still verifies against the licence's current trust roots.
public struct PolicyBundleRecord: Sendable, Equatable, Codable {
    public let json: String
    public let version: UInt64?
    /// The licence's bundle URL the bundle came from. A record without one (written
    /// before this field existed) is never used.
    public let sourceUrl: String?

    public init(json: String, version: UInt64?, sourceUrl: String? = nil) {
        self.json = json
        self.version = version
        self.sourceUrl = sourceUrl
    }
}

/// Cross-launch persistence for the last-`VALID` bundle + its version anchor.
///
/// By default `Magistrate` caches only in memory (per-instance). Pass a store to
/// `Magistrate(sdk:persistentStore:)` — e.g. `KeychainPolicyBundleStore()` — to
/// survive relaunch.
///
/// Implementations MUST use a rollback-resistant store (the platform secure
/// storage): the persisted `version` is the downgrade anchor, so an attacker who
/// can roll it back could replay an older validly-signed bundle. `load`/`save` are
/// called off the caller's task; keep them cheap and thread-safe.
public protocol PolicyBundleStore: Sendable {
    func load() -> PolicyBundleRecord?
    func save(_ record: PolicyBundleRecord)
}

/// One region's on-device proof for the in-request `/v1/decide` path (E1b): the
/// signed LocationProof envelope bound to the decision's challenge nonce.
public struct PolicyProof: Sendable {
    /// The bundle's canonical region string this proof answers.
    public let canonical: String

    /// The `isWithin` verdict for this region (bound to the challenge nonce).
    public let verdict: OctetVerdict

    /// The signed LocationProof envelope bytes — the same bytes uploaded on the
    /// server-fetched path. `nil` when the region couldn't be proven
    /// (`verdict.result == .indeterminate`); the engine then denies for missing
    /// coverage.
    public let proofBytes: Data?

    public init(canonical: String, verdict: OctetVerdict, proofBytes: Data?) {
        self.canonical = canonical
        self.verdict = verdict
        self.proofBytes = proofBytes
    }

    /// `proofBytes` as unpadded URL-safe base64 — the exact `proof_bytes_b64` the
    /// policy service's `POST /v1/decide` expects. `nil` when there is no proof.
    public var proofBytesBase64URL: String? {
        proofBytes.map { Magistrate.base64urlEncode($0) }
    }
}

/// The policy service's decision from `Magistrate.decide` — server-authoritative:
/// the engine ran the verifier over the submitted proofs and evaluated the policy.
public struct DecisionResult: Sendable, Equatable {
    /// The engine's decision, verbatim (e.g. `"permit"`, `"deny"`).
    public let decision: String
    /// What the host must do when enforcing this decision. **A permit with
    /// obligations is only a permit once the host has fulfilled every one of
    /// them.** The SDK surfaces obligations verbatim; it never enforces them. The
    /// engine returns them as authored, so a set can conflict (e.g. two TTLs).
    public let obligations: [PolicyObligation]
    /// The engine's reasons for the decision (diagnostic, human-readable).
    public let reasons: [String]
    /// The version of the policy bundle the engine decided against.
    public let policyVersion: UInt64
    /// The engine's audit commitment for this decision.
    public let proofRoot: String
    /// The decision's correlation id, from the engine's challenge.
    public let decisionRef: String
    /// The engine's signed decision receipt (compact JWS, EdDSA),
    /// verbatim — `nil` when the engine didn't return one. The SDK does NOT verify
    /// it: forward it to your backend, which verifies it against the engine's
    /// `/.well-known/decision-receipt-jwks.json` instead of trusting the device.
    public let receipt: String?
    /// The area the device claimed in the area proof it submitted for this check —
    /// what the phone disclosed, never coordinates. Read on the device from the proof
    /// Magistrate generated, not from the engine's response. `nil` when no area proof
    /// was submitted (the plan asks for none, or the area couldn't be proven).
    public let claimedArea: ClaimedArea?
    /// Why the location couldn't be decided, verbatim from the engine: `absence`,
    /// `stale`, `authenticity`, `unbound`, `inconsistent`, `undecidable` or `other`
    /// (later engines may add values). `nil` when the location was decided. A cause
    /// means the policy question's answer is UNKNOWN: the decision is the policy's
    /// fail-closed `on_indeterminate`, not a reading of where the device is.
    public let cause: String?
    /// The proof environment the decision's proofs came from, verbatim (`release`
    /// or `sandbox`). A production backend accepts only `release`. `nil` when the engine
    /// didn't say (engines before `env`).
    public let env: String?

    public init(decision: String, obligations: [PolicyObligation] = [], reasons: [String],
                policyVersion: UInt64, proofRoot: String, decisionRef: String,
                receipt: String? = nil, claimedArea: ClaimedArea? = nil,
                cause: String? = nil, env: String? = nil) {
        self.decision = decision
        self.obligations = obligations
        self.reasons = reasons
        self.policyVersion = policyVersion
        self.proofRoot = proofRoot
        self.decisionRef = decisionRef
        self.receipt = receipt
        self.claimedArea = claimedArea
        self.cause = cause
        self.env = env
    }

    /// A copy carrying `claimedArea`.
    func with(claimedArea: ClaimedArea?) -> DecisionResult {
        DecisionResult(decision: decision, obligations: obligations, reasons: reasons,
                       policyVersion: policyVersion, proofRoot: proofRoot,
                       decisionRef: decisionRef, receipt: receipt, claimedArea: claimedArea,
                       cause: cause, env: env)
    }

    /// `true` only when the engine returned `permit`. Anything else — `deny` or a
    /// decision this SDK doesn't know — is not a permit (fail-closed).
    public var isPermit: Bool { decision.lowercased() == "permit" }
}

/// One policy's decision inside a multi-policy check (see `Magistrate.decideMany`).
/// The engine decides each policy in the check independently, over the same
/// submitted proofs, and returns one of these per policy in `DecisionSet.results`.
public struct PolicyDecision: Sendable, Equatable {
    /// The policy name this result is for.
    public let policy: String
    /// The engine's ordinal of this result within the check.
    public let seq: Int
    /// The engine's decision, verbatim (e.g. `"permit"`, `"deny"`).
    public let decision: String
    /// What the host must do when enforcing this decision (see `DecisionResult.obligations`).
    public let obligations: [PolicyObligation]
    /// The engine's reasons for this policy's decision (diagnostic).
    public let reasons: [String]
    /// The version of this policy's bundle the engine decided against.
    public let policyVersion: UInt64
    /// The engine's audit commitment for this policy's decision.
    public let proofRoot: String
    /// This policy's signed decision receipt (compact JWS), verbatim — `nil` when the
    /// engine didn't return one; its `check_policies` names every policy in the check.
    /// The SDK does NOT verify it — forward it to your backend.
    public let receipt: String?
    /// Why the location couldn't be decided for this policy (see
    /// `DecisionResult.cause`); `nil` when it was decided.
    public let cause: String?
    /// The proof environment of the check's proofs (see `DecisionResult.env`).
    public let env: String?

    public init(policy: String, seq: Int, decision: String, obligations: [PolicyObligation] = [],
                reasons: [String], policyVersion: UInt64, proofRoot: String, receipt: String? = nil,
                cause: String? = nil, env: String? = nil) {
        self.policy = policy
        self.seq = seq
        self.decision = decision
        self.obligations = obligations
        self.reasons = reasons
        self.policyVersion = policyVersion
        self.proofRoot = proofRoot
        self.receipt = receipt
        self.cause = cause
        self.env = env
    }

    /// `true` only when the engine returned `permit` for this policy (fail-closed).
    public var isPermit: Bool { decision.lowercased() == "permit" }
}

/// The outcome of `Magistrate.decideMany`: the engine's per-policy decisions for a
/// single multi-policy check, all sharing one `decisionRef` and one set of submitted
/// proofs. Server-authoritative.
public struct DecisionSet: Sendable, Equatable {
    /// The check's correlation id, from the engine's challenge.
    public let decisionRef: String
    /// One `PolicyDecision` per policy in the check, in the engine's order.
    public let results: [PolicyDecision]
    /// The area the device claimed in the one area proof it submitted for the whole
    /// check — what the phone disclosed, never coordinates. Read on the device from the
    /// proof Magistrate generated, not from the engine's response. `nil` when no area
    /// proof was submitted (the merged plan asks for none, or the area couldn't be
    /// proven).
    public let claimedArea: ClaimedArea?

    public init(decisionRef: String, results: [PolicyDecision], claimedArea: ClaimedArea? = nil) {
        self.decisionRef = decisionRef
        self.results = results
        self.claimedArea = claimedArea
    }

    /// A copy carrying `claimedArea`.
    func with(claimedArea: ClaimedArea?) -> DecisionSet {
        DecisionSet(decisionRef: decisionRef, results: results, claimedArea: claimedArea)
    }

    /// This check's decision for `policy`, or `nil` if the engine returned none.
    public func forPolicy(_ policy: String) -> PolicyDecision? {
        results.first { $0.policy == policy }
    }

    /// `true` only when every policy in the check permitted (and the check is non-empty).
    public var allPermit: Bool { !results.isEmpty && results.allSatisfy { $0.isPermit } }
}

/// The area a device claimed in the area proof it sent with a decision: the named
/// place the phone disclosed (a country, a subdivision, or only "on Earth"), never
/// coordinates. It is read from the signed proof Magistrate generated, verbatim.
public struct ClaimedArea: Sendable, Equatable {
    /// How specific the claim is.
    public enum Level: String, Sendable, Equatable {
        /// The device claimed only that it is on Earth: its accuracy area may cross a
        /// border, so it named no country. `code` is `nil`.
        case earth
        /// The device claimed a country. `code` is ISO 3166-1 alpha-2 (e.g. `"GB"`).
        case country
        /// The device claimed a subdivision. `code` is ISO 3166-2 (e.g. `"US-CA"`).
        case subdivision
    }

    /// How specific the claim is.
    public let level: Level
    /// The claimed place's ISO code, as the proof carries it: ISO 3166-1 alpha-2 for
    /// `.country`, ISO 3166-2 for `.subdivision`, `nil` for `.earth`.
    public let code: String?

    public init(level: Level, code: String?) {
        self.level = level
        self.code = code
    }
}

/// An obligation the host must fulfil when enforcing a decision.
public enum PolicyObligation: Sendable, Equatable {
    /// Require a step-up authentication before acting on the decision.
    case stepUpAuth
    /// Record the decision on the named audit channel.
    case log(channel: String)
    /// Act on the decision only with the named reduced capability.
    case degrade(capability: String)
    /// The decision holds for this long (milliseconds), then must be re-decided.
    case ttl(durationMs: UInt64)
    /// A tenant-defined `x-<name>` obligation, opaque to the engine.
    case custom(name: String, args: [String])
    /// An obligation this SDK version doesn't recognise (e.g. added by a newer
    /// engine), as its raw JSON. Surfaced, never dropped: the host still has to
    /// handle it — treat one it can't fulfil as not permitted.
    case unknown(rawJson: String)
}

/// Why the policy service refused a `decide` request (its documented 4xx errors).
public enum DecideRejection: String, Sendable, Equatable {
    /// 400 — bad request body, bad base64, or a missing `decision_ref`.
    case badRequest
    /// 401 — the challenge is unknown or expired (challenges are short-lived).
    case challengeUnknownOrExpired
    /// 409 — the challenge was already used (challenges are single-use), or, on a
    /// multi-policy `decide`, the submitted policy set or a policy version differs
    /// from the set the challenge recorded (the challenge is then used up).
    case challengeReused
    /// 422 — the challenge was issued for a different policy.
    case policyScopeMismatch
}

/// Why the magistrate core refused a fetched bundle. Mirrors the core's
/// non-`VALID` `BundleStatus` cases; anything here means "do not trust this
/// bundle."
public enum BundleRejection: String, Sendable, Equatable {
    /// No matching trust root, or the Ed25519 signature didn't verify.
    case badSignature
    /// The bundle wasn't well-formed / couldn't be canonicalized.
    case malformed
    /// Validly signed but older than the device's known active version (the
    /// downgrade guard).
    case stale
    /// The bundle's proof-plan version or shape kind (or its content format) is one
    /// this Magistrate build doesn't know — fail closed, "update Magistrate / republish
    /// the policy" (maps `SlimError.unsupported` from `proofPlan`).
    case unsupportedPlan
}

/// Failures surfaced by `Magistrate.evaluate`. The facade guarantees one of
/// these on every failure; it never leaks a raw magistrate or transport error.
public enum PolicyError: Error, Sendable, Equatable {
    /// The license carries no policy bundle URL — policies aren't provisioned for this
    /// licence, so there's nothing to evaluate.
    case notProvisioned

    /// A trust root couldn't be used: its `alg` wasn't `Ed25519`, or its
    /// `publicKey` wasn't unpadded base64url of 32 raw Ed25519 bytes.
    case malformedTrustRoot(kid: String)

    /// Fetching the bundle from the license's `policyBundleFetchUrl` failed
    /// (transport error, non-2xx, or a non-UTF8 body). The associated string is
    /// a diagnostic, not for control flow.
    case bundleFetchFailed(String)

    /// The magistrate core rejected the bundle. Fail-closed — anything but
    /// `VALID`.
    case bundleRejected(BundleRejection)

    /// The verified bundle requires a region shape this SDK can't evaluate yet
    /// (v1 supports country / subdivision / disc / earth). Thrown rather than
    /// skipped: silently dropping a required region would let a decision pass
    /// without proving something the policy demands.
    case unsupportedRegion(canonical: String)

    /// The challenge nonce passed to `prove` was empty or, as UTF-8, exceeded the
    /// 512-byte session-binding cap. The engine's `/v1/decide/challenge` nonce is a
    /// short base64url string, so this indicates the wrong value was supplied.
    case invalidNonce

    /// `decide` needs the active license's id (`LicenseStatus.licenseId`) and it
    /// was `nil` — the SDK hasn't activated yet.
    case licenseIdUnavailable

    /// No required region could be proven, so there is nothing to submit. Thrown
    /// rather than sending an empty `proofs` set: the engine would treat that as a
    /// different (server-fetched) decision path, not this one. `details` has one
    /// entry per region — `"<canonical>: <verdict reason> — <verdict message>"` —
    /// saying why it produced no proof (e.g. `noFix` while the pipeline warms up).
    case noProofProduced(details: [String])

    /// The policy service refused the `decide` request. The associated string is
    /// the service's diagnostic, not for control flow.
    case decideRejected(DecideRejection, detail: String)

    /// The `decide` round-trip failed for another reason (transport error, an
    /// unexpected HTTP status, or an unreadable response). Diagnostic only.
    case decideFailed(String)

    /// A shape's disc-verdict proof couldn't be bound because semantic-binding v3
    /// isn't armed in this build (the SDK returned `notYetReleased`). Fail-closed:
    /// an unbound disc proof would read as a second area proof and the engine would
    /// drop the whole check, so the check is refused instead.
    case bindingUnavailable

    /// `Magistrate.decideMany` was called with an empty policy list or more than the
    /// engine's per-check maximum of 16. The associated value is the number requested.
    case invalidPolicySet(count: Int)
}
