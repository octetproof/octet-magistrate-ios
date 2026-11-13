// Sources/Magistrate/Magistrate.swift
// The Magistrate facade.
//
// Flow (app-driven; the decision itself stays server-authoritative):
//   1. Read the policy fields off the license: the bundle fetch URL + the Ed25519 trust roots.
//   2. Fetch the signed bundle from that URL.
//   3. `verifyBundle(...)` against the trust roots — FAIL-CLOSED (anything but
//      VALID throws).
//   4. `proofPlan(...)` reads the bundle's signed proof plan (level + disc shapes).
//   5. For each region, mint a decision-bound proof via `loc.isWithin(region:
//      decisionRef:)`.
// The host then submits the results (and the same `decisionRef`) to the policy
// service's `POST /v1/decide`, which makes the authoritative decision.
//
// `decideMany(license:policies:…)` runs the multi-policy variant (proof model v2):
// challenge the policy set, merge their plans, prove once against the merged plan,
// and get one decision per policy back.

import Foundation
@_spi(OctetModules) import OctetSDK

public final class Magistrate {

    private let sdk: OctetSdk
    private let fetch: (URL) async throws -> String

    /// JSON POST to the policy service (`/v1/decide/challenge`, `/v1/decide`):
    /// returns the HTTP status + body. Injected so tests run without a network.
    private let post: (URL, Data) async throws -> (Int, Data)

    /// Extract a bundle's monotonic version from its (already-verified) JSON, to
    /// anchor the downgrade guard: it is passed back to `verifyBundle` as
    /// `activeVersion` on the next refresh, so a validly-signed but older bundle
    /// is rejected as `.stale`.
    ///
    /// The public initializers use `bundleVersionFromContent` (the signed
    /// `content.version`). The test seam's default is `nil`, which leaves the
    /// downgrade check off; injected so the anchor logic is testable.
    private let bundleVersion: (String) -> UInt64?

    /// Last-known-`VALID` bundle: the fallback served when a refresh fails, and the
    /// source of the downgrade anchor. In-memory by default; backed by a
    /// `PolicyBundleStore` when one is supplied (cross-launch persistence).
    private let cache: BundleCache

    /// - Parameter sdk: a started `OctetSdk` (its `loc` mints the proofs).
    ///   Caches the last-`VALID` bundle in memory only (per-instance).
    public convenience init(sdk: OctetSdk) {
        self.init(sdk: sdk,
                  fetch: Magistrate.serviceFetch(sdk),
                  post: Magistrate.servicePost(sdk),
                  bundleVersion: Magistrate.bundleVersionFromContent,
                  store: nil)
    }

    /// - Parameters:
    ///   - sdk: a started `OctetSdk`.
    ///   - persistentStore: a rollback-resistant store (e.g.
    ///     `KeychainPolicyBundleStore()`) so the last-`VALID` bundle + its version
    ///     anchor survive relaunch.
    public convenience init(sdk: OctetSdk, persistentStore: PolicyBundleStore) {
        self.init(sdk: sdk,
                  fetch: Magistrate.serviceFetch(sdk),
                  post: Magistrate.servicePost(sdk),
                  bundleVersion: Magistrate.bundleVersionFromContent,
                  store: persistentStore)
    }

    /// Test seam: inject the bundle fetcher, policy-service transport, version
    /// extractor, and store. `internal` so tests can supply a bundle without a live
    /// network, exercise the downgrade anchor, and use an in-memory store — while
    /// the public paths go through the SDK's transport (`sendServiceRequest`).
    init(
        sdk: OctetSdk,
        fetch: @escaping (URL) async throws -> String,
        post: @escaping (URL, Data) async throws -> (Int, Data),
        bundleVersion: @escaping (String) -> UInt64? = { _ in nil },
        store: PolicyBundleStore? = nil
    ) {
        self.sdk = sdk
        self.fetch = fetch
        self.post = post
        self.bundleVersion = bundleVersion
        self.cache = BundleCache(store: store)
    }

    /// Verify the tenant's active policy bundle and prove every region it
    /// requires, all bound to `decisionRef`.
    ///
    /// - Parameters:
    ///   - license: the current `LicenseStatus` (pass `sdk.licenseStatus`); its
    ///     The policy fields carry the bundle URL + trust roots.
    ///   - decisionRef: the host-minted decision correlation id (1…256 bytes),
    ///     threaded into every proof so the uploads bind to this decision.
    /// - Throws: `PolicyError` on any failure (fail-closed on an untrusted or
    ///   unfetchable bundle, or an unsupported required region).
    public func evaluate(license: LicenseStatus, decisionRef: String) async throws -> PolicyEvaluation {
        // 1–3. Refresh the bundle: fetch → verify (fail-closed) → cache, falling
        //      back to the last-known-VALID bundle when a refresh fails.
        let active = try await resolveActiveBundle(license: license)

        // 4. Read the signed proof plan (proof model v2). The active bundle is
        //    trusted, so map a reader error fail-closed (malformed / unsupported plan).
        let plan = try Self.readPlan(bundleJson: active.json)

        // 5. A decision-bound verdict per disc shape. The plan's country/subdivision
        //    `level` is the phone's own area claim (decided from the area proof), not a
        //    region to query here, so `evaluate` surfaces the geometric shapes only.
        var results: [PolicyRegionResult] = []
        results.reserveCapacity(plan.shapes.count)
        for shape in plan.shapes {
            guard case let .disc(lat, lon, radiusM) = shape.region else { continue }
            let canonical = "disc:\(lat),\(lon),\(radiusM)"
            let region = OctetRegion.disc(center: LatLon(lat, lon), radiusMeters: radiusM)
            let verdict = await sdk.loc.isWithin(region: region, decisionRef: decisionRef)
            results.append(PolicyRegionResult(canonical: canonical, region: region, verdict: verdict))
        }
        return PolicyEvaluation(regions: results, servedFromCache: active.source == .cached)
    }

    /// Prove every region the tenant's active policy bundle requires, on device,
    /// for the in-request `POST /v1/decide` path (E1b) — returning the signed
    /// LocationProof envelopes bound to `nonce` instead of uploading them.
    ///
    /// Host flow: `POST /v1/decide/challenge` → `{decision_ref, nonce}` →
    /// `prove(license:nonce:)` → `POST /v1/decide` with the same `decision_ref` and
    /// `proofs: [{proof_bytes_b64}]`. The engine runs the verifier over the bytes
    /// and decides — server-authoritative. Send `attestationEnrolment()` along with
    /// the proofs: the decide carries it as `attestation_enrolment`, and a device the
    /// engine hasn't seen before can't pass the attestation check without it.
    ///
    /// - Parameters:
    ///   - license: the current `LicenseStatus` (its policy fields locate + trust the
    ///     bundle); the bundle is verified + cached exactly as in `evaluate`.
    ///   - nonce: the challenge nonce STRING from `/v1/decide/challenge`, verbatim.
    ///     Its UTF-8 bytes are the session-binding nonce — it is **not** base64url
    ///     decoded (the engine binds `nonce.as_bytes()`).
    /// - Returns: one `PolicyProof` per required region (a region that couldn't be
    ///   proven has `proofBytes == nil`).
    /// - Throws: `PolicyError` — fail-closed on an untrusted/unfetchable bundle, an
    ///   unsupported region, or an invalid nonce.
    public func prove(license: LicenseStatus, nonce: String) async throws -> [PolicyProof] {
        let nonceBytes = try Self.sessionNonceBytes(nonce)
        let active = try await resolveActiveBundle(license: license)
        return try await proveRequired(bundleJson: active.json, nonceBytes: nonceBytes)
    }

    /// The device's App Attest enrolment bundle, as the JSON string a
    /// `POST /v1/decide` carries in `attestation_enrolment` — for a host that submits
    /// the proofs from `prove(license:nonce:)` itself (the server-started flow).
    ///
    /// A proof carries only the App Attest assertion; the engine checks it against the
    /// device's key, which it learns from this bundle. Send it with every
    /// server-submitted decide: the engine enrols a key it hasn't seen and ignores the
    /// bundle for one it already has. `decide` and `decideMany` send it themselves.
    ///
    /// The bundle is attestation evidence, not a secret (about 5 KB). Pass the string
    /// on as a JSON **object**, not as a quoted string.
    ///
    /// - Returns: the bundle's JSON, or `nil` when the SDK holds no enrolment snapshot
    ///   (for example before the licence is activated).
    public func attestationEnrolment() -> String? {
        Octet.attestationEnrolmentBundle()?.jsonString()
    }

    /// The `env` a `POST /v1/decide/challenge` must carry for this device's proofs —
    /// for a host whose server starts the check (the server-started flow).
    ///
    /// An SDK signed in with a sandbox token uploads its proofs as sandbox, so the
    /// engine must look for them there; the challenge without `env` reads prod, finds
    /// none and answers UNKNOWN (`absence`). Send this to the server when the app asks
    /// for a check, and have the server put it on the challenge as `env` when it isn't
    /// `nil`. `decide` and `decideMany` send it themselves.
    ///
    /// - Returns: `"sandbox"` for a sandbox-token SDK, `nil` for prod (send no `env`).
    public func challengeEnv(license: LicenseStatus) -> String? {
        Self.challengeEnv(of: license)
    }

    static func challengeEnv(of license: LicenseStatus) -> String? {
        license.isSandbox ? "sandbox" : nil
    }

    /// Ask the policy service for a decision, proving on device every region the
    /// tenant's active bundle requires (the in-request path, E1b).
    ///
    /// Runs the whole handshake: `POST /v1/decide/challenge` → prove each required
    /// region bound to the challenge nonce (as `prove(license:nonce:)`) →
    /// `POST /v1/decide` with the signed proofs. The engine verifies the proofs and
    /// decides — server-authoritative. The policy service is the origin of the
    /// license's `policyBundleFetchUrl`; the policy name comes from the verified
    /// bundle, and `license_id` from `license.licenseId`. On an SDK signed in with a
    /// sandbox token, the challenge asks for the sandbox proofs (`env: sandbox`).
    ///
    /// - Parameters:
    ///   - license: the current `LicenseStatus` (pass `sdk.licenseStatus`).
    ///   - subjectId: optional subject id, for policies that use subject attributes.
    ///   - accountId: optional tenant hint.
    /// - Returns: the engine's `DecisionResult`. A `deny` is a result, not an error.
    ///   Its `claimedArea` is the area the device disclosed in the submitted area
    ///   proof (never coordinates), or `nil` when no area proof was submitted.
    /// - Throws: `PolicyError` — fail-closed on an untrusted/unfetchable bundle, an
    ///   unsupported region, no provable region, or a refused/failed request.
    public func decide(license: LicenseStatus,
                       subjectId: String? = nil,
                       accountId: String? = nil) async throws -> DecisionResult {
        guard let licenseId = license.licenseId, !licenseId.isEmpty else {
            throw PolicyError.licenseIdUnavailable
        }
        guard let engine = license.policyBundleFetchUrl.flatMap(Self.engineOrigin) else {
            throw PolicyError.notProvisioned
        }
        let active = try await resolveActiveBundle(license: license)
        guard let policy = Self.policyName(fromBundle: active.json) else {
            throw PolicyError.bundleRejected(.malformed)
        }
        // The area the submitted area proof claims, read off the proof as it is minted.
        var claimedArea: ClaimedArea? = nil
        let result = try await Self.runDecide(
            engine: engine, policy: policy, licenseId: licenseId,
            subjectId: subjectId, accountId: accountId, env: Self.challengeEnv(of: license),
            // The key's App Attest enrolment bundle (attestation object + snapshot
            // assertion + nonce₀), so the engine can enrol the key and verify this
            // decide's assertion against it. The proof itself carries
            // only the assertion: its object is bound to the activation challenge,
            // not to the proof. Nil when there's no enrolment snapshot.
            attestationEnrolment: attestationEnrolment(),
            post: post
        ) { nonce in
            let proofs = try await self.proveRequired(bundleJson: active.json,
                                                      nonceBytes: try Self.sessionNonceBytes(nonce))
            let submitted = proofs.compactMap { $0.proofBytesBase64URL }
            // Say why nothing could be proven — the verdicts carry the reason.
            if submitted.isEmpty {
                throw PolicyError.noProofProduced(details: proofs.map {
                    "\($0.canonical): \($0.verdict.reason) — \($0.verdict.message)"
                })
            }
            claimedArea = Self.claimedArea(from: proofs)
            return submitted
        }
        return result.with(claimedArea: claimedArea)
    }

    /// Ask the policy service for a decision on **several policies at once**: one
    /// challenge, one set of on-device proofs, one decision per policy.
    ///
    /// Runs the multi-policy handshake: `POST /v1/decide/challenge` with the
    /// `policies` names → fetch + verify each policy's bundle and read its plan →
    /// `mergePlans` them → prove **once** against the merged plan (one unbound area
    /// proof, skipped when the merged `level` is `.none`, plus one disc-verdict proof
    /// per merged shape), bound to the challenge nonce → `POST /v1/decide` with the
    /// same challenge set and the unlabelled proofs. The engine sorts the proofs,
    /// verifies each once, and decides every policy independently —
    /// server-authoritative. A `deny` (for any policy) is a result, not an error.
    ///
    /// - Parameters:
    ///   - license: the current `LicenseStatus` (pass `sdk.licenseStatus`); its policy
    ///     fields locate + trust the bundles. Each policy's bundle is fetched from the
    ///     license's `policyBundleFetchUrl` with the `policy` query parameter set to
    ///     the policy name.
    ///   - policies: the policy names to decide together — 1…16, matching the engine's
    ///     per-check maximum. The same set is echoed on `/v1/decide`, so a concurrent
    ///     republish that moves a version yields a 409 (`.challengeReused`).
    ///   - subjectId: optional subject id, for policies that use subject attributes.
    ///   - accountId: optional tenant hint.
    /// - Returns: the engine's `DecisionSet` — one `PolicyDecision` per policy. Its
    ///   `claimedArea` is the area the device disclosed in the check's one area proof
    ///   (never coordinates), or `nil` when no area proof was submitted.
    /// - Throws: `PolicyError` — fail-closed on an invalid policy set, an
    ///   untrusted/unfetchable bundle, an unsupported plan, no provable proof, or a
    ///   refused/failed request.
    public func decideMany(license: LicenseStatus,
                           policies: [String],
                           subjectId: String? = nil,
                           accountId: String? = nil) async throws -> DecisionSet {
        let names = try Self.normalizePolicies(policies)
        guard let licenseId = license.licenseId, !licenseId.isEmpty else {
            throw PolicyError.licenseIdUnavailable
        }
        guard let fetchUrlString = license.policyBundleFetchUrl,
              let engine = Self.engineOrigin(fetchUrlString) else {
            throw PolicyError.notProvisioned
        }
        let trustRoots = try license.policyTrustRoots.map { try Self.toTrustRoot($0) }

        // The area the check's one area proof claims, read off the proof as it is minted.
        var claimedArea: ClaimedArea? = nil
        let set = try await Self.runDecideMany(
            engine: engine, policies: names, licenseId: licenseId,
            subjectId: subjectId, accountId: accountId, env: Self.challengeEnv(of: license),
            attestationEnrolment: attestationEnrolment(),
            post: post
        ) { nonce in
            // Fetch + verify each policy's bundle fresh (fail-closed), read its plan,
            // and merge: the merged plan is what the whole check proves against. The
            // in-request decide path is online by definition, so this path does not use
            // the offline bundle cache (that backs `evaluate`).
            let nonceBytes = try Self.sessionNonceBytes(nonce)
            var plans: [ProofPlan] = []
            plans.reserveCapacity(names.count)
            for name in names {
                guard let url = URL(string: Self.bundleUrlFor(fetchUrlString, policy: name)) else {
                    throw PolicyError.notProvisioned
                }
                let json = try await self.fetch(url)
                let status = verifyBundle(bundleJson: json, trustRoots: trustRoots, activeVersion: nil)
                guard case .valid = status else {
                    throw PolicyError.bundleRejected(Self.rejection(from: status))
                }
                plans.append(try Self.readPlan(bundleJson: json))
            }
            let proofs = try await self.proveFromPlan(mergePlans(plans: plans), nonceBytes: nonceBytes)
            let submitted = proofs.compactMap { $0.proofBytesBase64URL }
            if submitted.isEmpty {
                throw PolicyError.noProofProduced(details: proofs.map {
                    "\($0.canonical): \($0.verdict.reason) — \($0.verdict.message)"
                })
            }
            claimedArea = Self.claimedArea(from: proofs)
            return submitted
        }
        return set.with(claimedArea: claimedArea)
    }

    /// Prove every region `bundleJson` requires, bound to `nonceBytes`, without
    /// uploading. Shared by `prove` and `decide`.
    private func proveRequired(bundleJson: String, nonceBytes: Data) async throws -> [PolicyProof] {
        try await proveFromPlan(try Self.readPlan(bundleJson: bundleJson), nonceBytes: nonceBytes)
    }

    /// Mint the proofs a (possibly merged) `plan` calls for, bound to `nonceBytes`:
    /// one area proof at its `level` (skipped when `.none`) plus one disc-verdict
    /// proof per shape — all from the same fix. Shared by the single-policy
    /// `proveRequired` and the multi-policy `decideMany` (which proves from the merged
    /// plan). sessionNonce binds each proof to the decision; no decisionRef ⇒ the
    /// bytes are returned in-process for `/v1/decide`.
    private func proveFromPlan(_ plan: ProofPlan, nonceBytes: Data) async throws -> [PolicyProof] {
        var proofs: [PolicyProof] = []
        proofs.reserveCapacity(plan.shapes.count + 1)

        // One area proof, unbound. A missing area proof (regionUnresolved /
        // insufficientPrecision) is not fatal here — the engine treats named-place
        // conditions as unknown — so we record the verdict (no bytes) and continue.
        if let level = Self.areaLevel(plan.level) {
            let verdict = await sdk.loc.proveArea(level: level, sessionNonce: nonceBytes, decisionRef: nil)
            proofs.append(PolicyProof(canonical: "area:\(plan.level)",
                                      verdict: verdict,
                                      proofBytes: verdict.proof?.proofBytes))
        }

        // One disc-verdict proof per shape, bound to the disc.
        for shape in plan.shapes {
            guard case let .disc(lat, lon, radiusM) = shape.region else { continue }
            let verdict = await sdk.loc.proveDiscVerdict(center: LatLon(lat, lon),
                                                         radiusMeters: radiusM,
                                                         sessionNonce: nonceBytes,
                                                         decisionRef: nil)
            // Never submit an unbound disc: when semantic-binding v3 isn't armed the SDK
            // returns `.notYetReleased` with no proof. An unbound disc would read as a
            // second area proof and the engine would drop the whole check — so fail closed.
            if verdict.reason == .notYetReleased { throw PolicyError.bindingUnavailable }
            proofs.append(PolicyProof(canonical: "disc:\(lat),\(lon),\(radiusM)",
                                      verdict: verdict,
                                      proofBytes: verdict.proof?.proofBytes))
        }
        return proofs
    }

    /// Read the signed proof plan, mapping the reader's `SlimError` fail-closed: an
    /// unknown plan version / shape kind / content format → `.unsupportedPlan`
    /// ("update Magistrate / republish"); anything else malformed → `.malformed`.
    /// Call `verify_bundle` first (as `resolveActiveBundle` does) — `proofPlan` does
    /// not check the signature.
    static func readPlan(bundleJson: String) throws -> ProofPlan {
        do {
            return try proofPlan(bundleJson: bundleJson)
        } catch let error as SlimError {
            switch error {
            case .Unsupported: throw PolicyError.bundleRejected(.unsupportedPlan)
            case .Malformed:   throw PolicyError.bundleRejected(.malformed)
            }
        }
    }

    /// The area proof's level, or `nil` for a shapes-only (`.none`) plan (no area proof).
    static func areaLevel(_ level: PlanLevel) -> OctetAreaLevel? {
        switch level {
        case .none:        return nil
        case .country:     return .country
        case .subdivision: return .subdivision
        }
    }

    /// The area the submitted area proof claims: the `area:` entry of `proofs` that
    /// carries proof bytes, mapped by `claimedArea(from region:)`. `nil` when there is no
    /// such proof (shapes-only plan, or the area couldn't be proven).
    static func claimedArea(from proofs: [PolicyProof]) -> ClaimedArea? {
        guard let area = proofs.first(where: { $0.canonical.hasPrefix("area:") }),
              area.proofBytes != nil,
              let proof = area.verdict.proof else { return nil }
        return claimedArea(from: proof.claimedRegion)
    }

    /// Map a proof's `claimedRegion` to Magistrate's `ClaimedArea`, verbatim. Only a
    /// country, a subdivision or Earth is an area claim; anything else (an area proof
    /// never carries one), or a country/subdivision with an empty code, is `nil` —
    /// never a guessed value.
    static func claimedArea(from region: ProofRegion) -> ClaimedArea? {
        switch region {
        case .earth:
            return ClaimedArea(level: .earth, code: nil)
        case .country(let iso):
            return iso.isEmpty ? nil : ClaimedArea(level: .country, code: iso)
        case .subdivision(let iso):
            return iso.isEmpty ? nil : ClaimedArea(level: .subdivision, code: iso)
        case .city, .ellipse, .h3PolygonSet, .boundingBox3D:
            return nil
        }
    }

    /// The session-binding nonce bytes: the challenge nonce STRING's UTF-8 bytes,
    /// verbatim (NOT base64url-decoded — the engine binds `nonce.as_bytes()`).
    /// Enforces the session-binding bounds (1…512 B).
    static func sessionNonceBytes(_ nonce: String) throws -> Data {
        let bytes = Data(nonce.utf8)
        guard (1...512).contains(bytes.count) else { throw PolicyError.invalidNonce }
        return bytes
    }

    // MARK: - Bundle refresh (step 3)

    private enum BundleSource { case fresh, cached }
    private struct ActiveBundle {
        let json: String
        let source: BundleSource
    }

    /// Fetch the current bundle, verify it against the license's trust roots with
    /// the cached version as the downgrade anchor, and adopt it when `VALID`.
    /// On any failure (unreachable, bad signature, malformed, or a downgrade),
    /// fall back to the last-known-`VALID` cached bundle; with no such cache, fail
    /// closed. The cache counts only if it came from this licence's bundle URL and
    /// still verifies against the current trust roots (`usableCache`), so a rotated
    /// key, another licence's bundle, or a store tampered with is never served.
    private func resolveActiveBundle(license: LicenseStatus) async throws -> ActiveBundle {
        guard let urlString = license.policyBundleFetchUrl,
              let url = URL(string: urlString) else {
            throw PolicyError.notProvisioned
        }
        // Empty trust roots ⇒ nothing can verify ⇒ the core returns a non-VALID
        // status ⇒ fail-closed below (never adopts an unverifiable bundle).
        let trustRoots = try license.policyTrustRoots.map { try Self.toTrustRoot($0) }
        let cached = Self.usableCache(cache.current(), bundleUrl: urlString) {
            verifyBundle(bundleJson: $0, trustRoots: trustRoots, activeVersion: nil) == .valid
        }

        // Fetch (a transport failure is recoverable if we hold a cached bundle).
        var freshJson: String? = nil
        var fetchError: Error? = nil
        do {
            freshJson = try await fetch(url)
        } catch let error as PolicyError {
            fetchError = error
        } catch {
            fetchError = PolicyError.bundleFetchFailed(String(describing: error))
        }

        // Verify the fresh bundle, anchored to the cached version (downgrade guard).
        var freshStatus: BundleStatus? = nil
        if let json = freshJson {
            freshStatus = verifyBundle(bundleJson: json,
                                       trustRoots: trustRoots,
                                       activeVersion: cached?.version)
        }

        switch Self.resolve(freshStatus: freshStatus, hasCached: cached != nil) {
        case .adoptFresh:
            let json = freshJson!
            // Carry the anchor forward if the fresh bundle's version can't be read,
            // so a VALID-but-unreadable bundle never regresses the downgrade anchor.
            let version = bundleVersion(json) ?? cached?.version
            cache.adopt(PolicyBundleRecord(json: json, version: version, sourceUrl: urlString))
            return ActiveBundle(json: json, source: .fresh)
        case .keepCached:
            return ActiveBundle(json: cached!.json, source: .cached)
        case .rejectFresh:
            throw PolicyError.bundleRejected(Self.rejection(from: freshStatus!))
        case .fetchFailed:
            throw fetchError ?? PolicyError.bundleFetchFailed("unreachable")
        }
    }

    /// Pure refresh decision — kept side-effect-free so the fail-closed/fallback
    /// policy is unit-testable without the network or the native core.
    ///
    /// - `.adoptFresh` when the fresh bundle verified `VALID`.
    /// - `.keepCached` when it didn't (or wasn't fetched) but a trusted cache exists.
    /// - `.rejectFresh` when it verified non-`VALID` and there is no cache.
    /// - `.fetchFailed` when it wasn't fetched at all and there is no cache.
    enum BundleResolution: Equatable { case adoptFresh, keepCached, rejectFresh, fetchFailed }

    /// The cached record, if Magistrate may use it for `bundleUrl`: it came from that
    /// URL and its bundle still verifies (`verifies`, the real core in production).
    /// Otherwise nil — neither a fallback nor a downgrade anchor. Pure, so testable
    /// without the native core.
    static func usableCache(_ record: PolicyBundleRecord?, bundleUrl: String,
                            verifies: (String) -> Bool) -> PolicyBundleRecord? {
        guard let record, record.sourceUrl == bundleUrl, verifies(record.json) else { return nil }
        return record
    }

    static func resolve(freshStatus: BundleStatus?, hasCached: Bool) -> BundleResolution {
        if case .valid? = freshStatus { return .adoptFresh }
        if hasCached { return .keepCached }
        if freshStatus != nil { return .rejectFresh }
        return .fetchFailed
    }

    // MARK: - Mapping

    /// Map a `PolicyTrustRoot` (base64url-encoded key) to the magistrate
    /// core's `TrustRoot` (raw bytes). Rejects anything but a 32-byte Ed25519
    /// key.
    static func toTrustRoot(_ r: PolicyTrustRoot) throws -> TrustRoot {
        guard r.alg == "Ed25519",
              let key = base64urlDecode(r.publicKey),
              key.count == 32 else {
            throw PolicyError.malformedTrustRoot(kid: r.kid)
        }
        return TrustRoot(kid: r.kid, publicKey: key)
    }


    static func rejection(from status: BundleStatus) -> BundleRejection {
        switch status {
        case .badSignature: return .badSignature
        case .malformed: return .malformed
        case .stale: return .stale
        case .valid: return .malformed  // unreachable: the caller guards `.valid`
        @unknown default: return .malformed
        }
    }

    /// Read a bundle's monotonic version from `content.version` (u64) — the field
    /// `verifyBundle`'s downgrade guard compares against `activeVersion`
    /// (magistrate core `opl-ffi/src/lib.rs`). This is the value cached and passed
    /// back on the next refresh to reject a downgrade as `.stale`. Returns nil when
    /// absent or not a non-negative integer; the bundle is already verified when
    /// this is read, so a missing version just leaves the anchor un-advanced.
    static func bundleVersionFromContent(_ json: String) -> UInt64? {
        guard let data = json.data(using: .utf8) else { return nil }
        return (try? JSONDecoder().decode(BundleEnvelope.self, from: data))?.content?.version
    }

    private struct BundleEnvelope: Decodable {
        let content: Content?
        struct Content: Decodable { let version: UInt64? }
    }

    /// Encode raw bytes as unpadded URL-safe base64 (the `proof_bytes_b64` form).
    static func base64urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode unpadded (or padded) base64url into raw bytes.
    static func base64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+")
                 .replacingOccurrences(of: "_", with: "/")
        let remainder = b.count % 4
        if remainder != 0 {
            b += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: b)
    }

    // MARK: - Decide (in-request path, E1b)

    /// The decide handshake, free of `OctetSdk` so it is unit-testable: challenge
    /// → `prove(nonce)` → decide. `prove` returns the `proof_bytes_b64` strings of
    /// the regions that could be proven.
    static func runDecide(
        engine: URL,
        policy: String,
        licenseId: String,
        subjectId: String?,
        accountId: String?,
        env: String? = nil,
        attestationEnrolment: String? = nil,
        post: (URL, Data) async throws -> (Int, Data),
        prove: (String) async throws -> [String]
    ) async throws -> DecisionResult {
        let challengeURL = engine.appendingPathComponent("v1/decide/challenge")
        let challenge: ChallengeResponse = try decodeResponse(
            try await postJSON(post, challengeURL, ChallengeRequest(policy: policy, accountId: accountId,
                                                              env: env)),
            from: challengeURL)

        let proofs = try await prove(challenge.nonce)
        // Never send an empty set: the engine reads `proofs: []` as the
        // server-fetched path, which this call is not.
        guard !proofs.isEmpty else { throw PolicyError.noProofProduced(details: []) }

        let decideURL = engine.appendingPathComponent("v1/decide")
        let body = try await postJSON(
            post, decideURL,
            DecideRequest(policy: policy,
                          licenseId: licenseId,
                          decisionRef: challenge.decisionRef,
                          proofs: proofs.map { DecideRequest.Proof(proofBytesB64: $0) },
                          subjectId: subjectId,
                          accountId: accountId,
                          attestationEnrolment: attestationEnrolment.flatMap(EnrolmentBundle.init(json:))))
        let response: DecideResponse = try decodeResponse(body, from: decideURL)
        return DecisionResult(decision: response.decision,
                              obligations: try obligations(fromDecideResponse: body),
                              reasons: response.reasons ?? [],
                              policyVersion: response.policyVersion,
                              proofRoot: response.proofRoot,
                              decisionRef: challenge.decisionRef,
                              receipt: response.receipt,
                              cause: response.cause,
                              env: response.env)
    }

    /// The multi-policy decide handshake (proof model v2), free of `OctetSdk` so it is
    /// unit-testable: `challenge(policies)` → `prove(nonce)` → decide. Both the challenge
    /// and the decide carry the policy **names** (the same set, any order); the engine
    /// recorded each policy's active version at challenge time and rejects a set/version
    /// drift with a 409. `prove` returns the unlabelled `proof_bytes_b64` strings.
    static func runDecideMany(
        engine: URL,
        policies: [String],
        licenseId: String,
        subjectId: String?,
        accountId: String?,
        env: String? = nil,
        attestationEnrolment: String? = nil,
        post: (URL, Data) async throws -> (Int, Data),
        prove: (String) async throws -> [String]
    ) async throws -> DecisionSet {
        let challengeURL = engine.appendingPathComponent("v1/decide/challenge")
        let challenge: MultiChallengeResponse = try decodeResponse(
            try await postJSON(post, challengeURL, MultiChallengeRequest(policies: policies, accountId: accountId,
                                                                        env: env)),
            from: challengeURL)

        let proofs = try await prove(challenge.nonce)
        // Never send an empty set: the engine reads `proofs: []` as the server-fetched
        // path, which this call is not.
        guard !proofs.isEmpty else { throw PolicyError.noProofProduced(details: []) }

        let decideURL = engine.appendingPathComponent("v1/decide")
        let body = try await postJSON(
            post, decideURL,
            MultiDecideRequest(policies: policies,
                               licenseId: licenseId,
                               decisionRef: challenge.decisionRef,
                               proofs: proofs.map { DecideRequest.Proof(proofBytesB64: $0) },
                               subjectId: subjectId,
                               accountId: accountId,
                               attestationEnrolment: attestationEnrolment.flatMap(EnrolmentBundle.init(json:))))
        return try decisionSet(fromDecideResponse: body, fallbackDecisionRef: challenge.decisionRef)
    }

    /// Parse a multi-policy `/v1/decide` response `{decision_ref, results: [...]}`.
    /// Fails closed on a missing/unreadable `results` array.
    static func decisionSet(fromDecideResponse data: Data, fallbackDecisionRef: String) throws -> DecisionSet {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PolicyError.decideFailed("unreadable response from /v1/decide")
        }
        guard let rawResults = object["results"] as? [Any] else {
            throw PolicyError.decideFailed("decide response missing results")
        }
        let results = try rawResults.map { try policyDecision($0) }
        return DecisionSet(decisionRef: (object["decision_ref"] as? String) ?? fallbackDecisionRef,
                           results: results)
    }

    /// Parse one `results[]` entry: `{policy, seq, decision, obligations, reasons,
    /// policy_version, proof_root, receipt, cause, env}`. Fails closed on a missing required field.
    static func policyDecision(_ raw: Any) throws -> PolicyDecision {
        guard let obj = raw as? [String: Any] else {
            throw PolicyError.decideFailed("decide result is not an object")
        }
        guard let policy = obj["policy"] as? String else { throw PolicyError.decideFailed("result missing policy") }
        guard let seq = obj["seq"] as? NSNumber, !CFNumberIsFloatType(seq) else {
            throw PolicyError.decideFailed("unreadable seq")
        }
        guard let decision = obj["decision"] as? String else { throw PolicyError.decideFailed("result missing decision") }
        guard let pv = obj["policy_version"] as? NSNumber, !CFNumberIsFloatType(pv) else {
            throw PolicyError.decideFailed("unreadable policy_version")
        }
        guard let proofRoot = obj["proof_root"] as? String else { throw PolicyError.decideFailed("result missing proof_root") }
        let obligations: [PolicyObligation]
        if let rawOb = obj["obligations"], !(rawOb is NSNull) {
            guard let list = rawOb as? [Any] else { throw PolicyError.decideFailed("unreadable obligations") }
            obligations = list.map(obligation)
        } else {
            obligations = []
        }
        return PolicyDecision(policy: policy, seq: seq.intValue, decision: decision,
                              obligations: obligations, reasons: (obj["reasons"] as? [String]) ?? [],
                              policyVersion: pv.uint64Value, proofRoot: proofRoot,
                              receipt: obj["receipt"] as? String,
                              cause: obj["cause"] as? String,
                              env: obj["env"] as? String)
    }

    /// Trim + drop blank names, then enforce the engine's per-check bound of 1…16
    /// policies. Throws `.invalidPolicySet` (reporting the requested count) otherwise.
    static func normalizePolicies(_ policies: [String]) throws -> [String] {
        let names = policies
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard (1...16).contains(names.count) else { throw PolicyError.invalidPolicySet(count: policies.count) }
        return names
    }

    /// The bundle-fetch URL for `policy`: `fetchUrl` with its `policy` query parameter
    /// set to `policy` (any existing one replaced), every other part preserved. One
    /// engine serves every policy's bundle at `GET /v1/bundle?policy=…`.
    static func bundleUrlFor(_ fetchUrl: String, policy: String) -> String {
        guard var comps = URLComponents(string: fetchUrl) else { return fetchUrl }
        var items = (comps.queryItems ?? []).filter { $0.name != "policy" }
        items.append(URLQueryItem(name: "policy", value: policy))
        comps.queryItems = items
        return comps.string ?? fetchUrl
    }

    /// POST `body` as JSON and return a 2xx response body; map the policy
    /// service's documented 4xx errors to `DecideRejection`, anything else to
    /// `decideFailed`.
    private static func postJSON<Request: Encodable>(
        _ post: (URL, Data) async throws -> (Int, Data),
        _ url: URL,
        _ body: Request
    ) async throws -> Data {
        let status: Int
        let data: Data
        do {
            (status, data) = try await post(url, try JSONEncoder().encode(body))
        } catch let error as PolicyError {
            throw error
        } catch {
            throw PolicyError.decideFailed(String(describing: error))
        }
        guard (200..<300).contains(status) else {
            let detail = errorDetail(data)
            if let rejection = decideRejection(status: status) {
                throw PolicyError.decideRejected(rejection, detail: detail)
            }
            throw PolicyError.decideFailed("HTTP \(status): \(detail)")
        }
        return data
    }

    private static func decodeResponse<Response: Decodable>(_ data: Data, from url: URL) throws -> Response {
        do {
            return try JSONDecoder().decode(Response.self, from: data)
        } catch {
            throw PolicyError.decideFailed("unreadable response from \(url.path)")
        }
    }

    /// The `obligations` of a `/v1/decide` response. Absent ⇒ none. Present but not
    /// an array ⇒ `decideFailed`: the obligations can't be known, so neither can
    /// what the decision requires.
    static func obligations(fromDecideResponse data: Data) throws -> [PolicyObligation] {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PolicyError.decideFailed("unreadable response from /v1/decide")
        }
        guard let raw = object["obligations"], !(raw is NSNull) else { return [] }
        guard let list = raw as? [Any] else {
            throw PolicyError.decideFailed("unreadable obligations")
        }
        return list.map(obligation)
    }

    /// Map one obligation in the engine's externally-tagged form (`"StepUpAuth"`,
    /// `{"Log":{"channel":…}}`, `{"Ttl":{"duration":{"ms":…}}}`, …). Anything
    /// unrecognised or malformed becomes `.unknown(rawJson)` — never dropped.
    static func obligation(_ raw: Any) -> PolicyObligation {
        if let tag = raw as? String, tag == "StepUpAuth" { return .stepUpAuth }
        if let object = raw as? [String: Any], object.count == 1,
           let (tag, value) = object.first, let fields = value as? [String: Any] {
            switch tag {
            case "Log":
                if let channel = fields["channel"] as? String { return .log(channel: channel) }
            case "Degrade":
                if let capability = fields["capability"] as? String { return .degrade(capability: capability) }
            case "Ttl":
                if let duration = fields["duration"] as? [String: Any],
                   let ms = duration["ms"] as? NSNumber, !CFNumberIsFloatType(ms), ms.int64Value >= 0 {
                    return .ttl(durationMs: ms.uint64Value)
                }
            case "Custom":
                if let name = fields["name"] as? String, let args = fields["args"] as? [String] {
                    return .custom(name: name, args: args)
                }
            default:
                break
            }
        }
        let json = (try? JSONSerialization.data(withJSONObject: raw, options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes]))
            .map { String(decoding: $0, as: UTF8.self) } ?? String(describing: raw)
        return .unknown(rawJson: json)
    }

    static func decideRejection(status: Int) -> DecideRejection? {
        switch status {
        case 400: return .badRequest
        case 401: return .challengeUnknownOrExpired
        case 409: return .challengeReused
        case 422: return .policyScopeMismatch
        default: return nil
        }
    }

    /// The service's `{"error": "…"}` message, else the (truncated) raw body.
    static func errorDetail(_ data: Data) -> String {
        struct ErrorBody: Decodable { let error: String }
        if let body = try? JSONDecoder().decode(ErrorBody.self, from: data) { return body.error }
        return String(decoding: data.prefix(200), as: UTF8.self)
    }

    /// The policy service's base URL: the origin (scheme, host, port) of the
    /// bundle fetch URL — one engine serves `/v1/bundle` and `/v1/decide*`.
    static func engineOrigin(_ fetchUrl: String) -> URL? {
        guard let parsed = URLComponents(string: fetchUrl),
              let scheme = parsed.scheme, let host = parsed.host, !host.isEmpty else { return nil }
        var origin = URLComponents()
        origin.scheme = scheme
        origin.host = host
        origin.port = parsed.port
        return origin.url
    }

    /// The policy name from a verified bundle (`content.policy.name`) — the
    /// `policy` the policy service expects on the challenge and the decision.
    static func policyName(fromBundle json: String) -> String? {
        struct Envelope: Decodable {
            let content: Content?
            struct Content: Decodable {
                let policy: Policy?
                struct Policy: Decodable { let name: String? }
            }
        }
        guard let data = json.data(using: .utf8),
              let name = (try? JSONDecoder().decode(Envelope.self, from: data))?.content?.policy?.name,
              !name.isEmpty else { return nil }
        return name
    }

    // Wire shapes of the engine's decide API. Optional fields are omitted when nil.

    struct ChallengeRequest: Encodable {
        let policy: String
        let accountId: String?
        /// `"sandbox"` when the SDK runs on a sandbox token, so the engine reads the proofs
        /// it uploaded as sandbox. `nil` is omitted, which the engine reads as prod.
        let env: String?
        enum CodingKeys: String, CodingKey { case policy, accountId = "account_id", env }
    }

    struct ChallengeResponse: Decodable {
        let decisionRef: String
        let nonce: String
        enum CodingKeys: String, CodingKey { case decisionRef = "decision_ref", nonce }
    }

    struct DecideRequest: Encodable {
        let policy: String
        let licenseId: String
        let decisionRef: String
        let proofs: [Proof]
        let subjectId: String?
        let accountId: String?
        let attestationEnrolment: EnrolmentBundle?
        struct Proof: Encodable {
            let proofBytesB64: String
            enum CodingKeys: String, CodingKey { case proofBytesB64 = "proof_bytes_b64" }
        }
        enum CodingKeys: String, CodingKey {
            case policy, proofs
            case licenseId = "license_id", decisionRef = "decision_ref"
            case subjectId = "subject_id", accountId = "account_id"
            case attestationEnrolment = "attestation_enrolment"
        }
    }

    /// The App Attest enrolment bundle as it rides `attestation_enrolment`: the frozen
    /// `v: 1` form of `AttestationEnrolmentBundle.jsonString()`, carried as a JSON object.
    struct EnrolmentBundle: Codable, Equatable {
        let v: Int
        let keyId: String
        let appAttestAttestation: String
        let appAttestAssertion: String
        let attestationNonce: String
        enum CodingKeys: String, CodingKey {
            case v
            case keyId = "key_id"
            case appAttestAttestation = "app_attest_attestation"
            case appAttestAssertion = "app_attest_assertion"
            case attestationNonce = "attestation_nonce"
        }
        init?(json: String) {
            guard let bundle = try? JSONDecoder().decode(Self.self, from: Data(json.utf8)) else { return nil }
            self = bundle
        }
    }

    struct DecideResponse: Decodable {
        let decision: String
        let reasons: [String]?
        let policyVersion: UInt64
        let proofRoot: String
        let receipt: String?
        let cause: String?
        let env: String?
        enum CodingKeys: String, CodingKey {
            case decision, reasons, receipt, cause, env
            case policyVersion = "policy_version", proofRoot = "proof_root"
        }
    }

    // Multi-policy decide (proof model v2). Both the challenge and the decide carry the
    // policy names; the response records `[{policy, version}]` for the caller's info, and
    // the engine compares those recorded versions itself (a drift ⇒ 409).

    struct MultiChallengeRequest: Encodable {
        let policies: [String]
        let accountId: String?
        /// `"sandbox"` when the SDK runs on a sandbox token, so the engine reads the proofs
        /// it uploaded as sandbox. `nil` is omitted, which the engine reads as prod.
        let env: String?
        enum CodingKeys: String, CodingKey { case policies, accountId = "account_id", env }
    }

    /// A policy + the version the engine recorded for it at challenge time.
    struct ChallengedPolicy: Codable, Equatable {
        let policy: String
        let version: UInt64
    }

    struct MultiChallengeResponse: Decodable {
        let decisionRef: String
        let nonce: String
        let policies: [ChallengedPolicy]
        enum CodingKeys: String, CodingKey { case decisionRef = "decision_ref", nonce, policies }
    }

    struct MultiDecideRequest: Encodable {
        let policies: [String]
        let licenseId: String
        let decisionRef: String
        let proofs: [DecideRequest.Proof]
        let subjectId: String?
        let accountId: String?
        let attestationEnrolment: EnrolmentBundle?
        enum CodingKeys: String, CodingKey {
            case policies, proofs
            case licenseId = "license_id", decisionRef = "decision_ref"
            case subjectId = "subject_id", accountId = "account_id"
            case attestationEnrolment = "attestation_enrolment"
        }
    }

    // MARK: - Transport
    //
    // Engine calls go through `OctetSdk.sendServiceRequest`, so they follow the
    // integrator's `TransportPolicy` — gateway modes, pins, fallbackToDirect —
    // exactly like the SDK's own traffic, instead of going straight to the engine.

    static func servicePost(_ sdk: OctetSdk) -> (URL, Data) async throws -> (Int, Data) {
        { url, body in
            let response: OctetServiceResponse
            do {
                response = try await sdk.sendServiceRequest(OctetServiceRequest(
                    method: .post, url: url, headers: ["Content-Type": "application/json"], body: body))
            } catch {
                throw PolicyError.decideFailed(String(describing: error))
            }
            return (response.status, response.body)
        }
    }

    static func serviceFetch(_ sdk: OctetSdk) -> (URL) async throws -> String {
        { url in
            let response: OctetServiceResponse
            do {
                response = try await sdk.sendServiceRequest(OctetServiceRequest(method: .get, url: url))
            } catch {
                throw PolicyError.bundleFetchFailed(String(describing: error))
            }
            guard (200..<300).contains(response.status) else {
                throw PolicyError.bundleFetchFailed("HTTP \(response.status)")
            }
            guard let json = String(data: response.body, encoding: .utf8) else {
                throw PolicyError.bundleFetchFailed("non-UTF8 body")
            }
            return json
        }
    }
}
