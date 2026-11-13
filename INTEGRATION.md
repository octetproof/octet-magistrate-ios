# Integrating Magistrate (iOS)

> [!IMPORTANT]
> **You enforce the answer.** Magistrate returns your policy's answer (YES, NO or
> UNKNOWN) with a receipt signed by Octet. It does not block or allow anything by
> itself. Your backend verifies the receipt and decides what happens to the request;
> if it ignores the answer, nothing is enforced.

## Prerequisites

- iOS 16+, Swift 5.9+.
- Octet SDK 3.1.2, the exact version this Magistrate release pins (see README.md).
  Checks from a sandbox build (debug or simulator builds signed in with a sandbox
  token) also need a sandbox app registered on your license.
- Your app registered on your Octet license. OctetSDK signs in with
  hardware attestation, so there's no license key to paste. Start it with `OctetConfig()`.
- Both SwiftPM packages added: `octet-magistrate-ios` (product `Magistrate`) and
  `octet-sdk-ios` (product `OctetSDK`, pinned to Magistrate's OctetSDK version) — you
  call `Octet.start` yourself, and SwiftPM doesn't re-export OctetSDK through Magistrate.
- Location and motion usage descriptions in your `Info.plist`, and the App Attest
  capability, since the decision is backed by an attested on-device location proof.

## Getting a `Magistrate`

`Magistrate` is a thin facade over a started `OctetSdk`. Start the SDK, then wrap it:

```swift
import OctetSDK
import Magistrate

let sdk = try await Octet.start(
    // No licence key: OctetSDK signs in with App Attest (or a sandbox token).
    config: OctetConfig(),
    startPosition: nil
)
let magistrate = Magistrate(sdk: sdk)
```

To keep the verified policy bundle across launches, pass a persistent store:

```swift
let magistrate = Magistrate(sdk: sdk, persistentStore: KeychainPolicyBundleStore())
```

## API

The check methods are `async throws` and take the `LicenseStatus` from
`sdk.licenseStatus`.

### `decide` — the one-call decision

```swift
func decide(license: LicenseStatus,
            subjectId: String? = nil,
            accountId: String? = nil) async throws -> DecisionResult
```

Runs the whole exchange in one call: fetch the active bundle → verify it (fail-closed)
→ request a single-use challenge → produce the required location proof bound to that
challenge → submit → return the decision. Do not manage the challenge yourself;
`decide` owns it.

`DecisionResult`:

| field | type | meaning |
| --- | --- | --- |
| `decision` | `String` | e.g. `permit` / `deny` |
| `isPermit` | `Bool` | `decision == "permit"` |
| `obligations` | `[PolicyObligation]` | conditions attached to a permit |
| `reasons` | `[String]` | human-readable basis, especially on a deny |
| `policyVersion` | `UInt64` | version of the policy that decided |
| `proofRoot` | `String` | Merkle root committing the submitted proofs |
| `decisionRef` | `String` | opaque reference for later verification |
| `receipt` | `String?` | the engine's signed decision receipt: verify it on your server (below) |
| `claimedArea` | `ClaimedArea?` | the area the device disclosed in its proof (a country, a subdivision or only "Earth"); never coordinates |
| `cause` | `String?` | why the location couldn't be decided (see below); nil when it was |
| `env` | `String?` | the proofs' environment: `release` or `sandbox` |

A **denial is a returned `DecisionResult`** (`isPermit == false`), not a thrown error.
Read it as YES, NO or UNKNOWN (below); `reasons` are diagnostic.

### `decideMany` — several policies, one proof

```swift
func decideMany(license: LicenseStatus,
                policies: [String],
                subjectId: String? = nil,
                accountId: String? = nil) async throws -> DecisionSet
```

Decides 1 to 16 policies in one check: the device proves once, and the engine decides
each policy from the same proof. `DecisionSet` has the shared `decisionRef`, the
`claimedArea`, and one `PolicyDecision` per policy in `results` (look one up with
`forPolicy(_:)`), each with its own `decision`, `cause`, `env` and `receipt`.

### `prove` / `evaluate` — lower-level building blocks

```swift
func prove(license: LicenseStatus, nonce: String) async throws -> [PolicyProof]
func evaluate(license: LicenseStatus, decisionRef: String) async throws -> PolicyEvaluation
```

`prove` mints the location proofs for the bundle's required regions bound to a nonce;
`evaluate` reports per-region verdicts (`PolicyRegionResult`) without contacting the
decision endpoint. Most integrations only need `decide`.

### Server-started checks: `prove`, `attestationEnrolment` and `challengeEnv`

Your backend can run the check itself, so the decision never passes through the app:

1. The app asks the backend for a check and sends `challengeEnv(license:)` with the request.
   It's `"sandbox"` when the SDK was signed in with a sandbox token, else `nil`.
2. The backend calls `POST /v1/decide/challenge`, with `"env": "sandbox"` when the app
   sent it, and sends the `nonce` to the app. Without it, a sandbox build's check reads
   prod, finds no proofs and answers UNKNOWN (`absence`).
3. The app calls `prove(license:nonce:)` and sends the proofs, **and**
   `attestationEnrolment()`, to the backend.
4. The backend calls `POST /v1/decide` with your licence id as `license_id` (always
   required: the engine checks the proofs against your licence's registered apps), the
   same `decision_ref`, the proofs as
   `proofs: [{"proof_bytes_b64": …}]` and, when the app sent one, the enrolment as
   `attestation_enrolment` (a JSON object, not a quoted string).

```swift
let env = magistrate.challengeEnv(license: license)   // "sandbox" or nil
let nonce = try await myBackend.startCheck(env: env)
let proofs = try await magistrate.prove(license: license, nonce: nonce)
let enrolment = magistrate.attestationEnrolment()   // App Attest enrolment bundle (JSON)
try await myBackend.submit(proofs: proofs.compactMap(\.proofBytesBase64URL), enrolment: enrolment)
```

On iOS the enrolment is required for a device the engine hasn't seen before: a proof
carries only the App Attest assertion, and the engine learns the device's key from the
enrolment. Send it every time; the engine ignores it for a key it already has. `decide`
and `decideMany` send it for you.

The engine enrols a key only from a decide that carries the proofs, as in step 4. A
decide where the engine fetches the proofs itself (no `proofs` in the body) ignores
`attestation_enrolment`, so an iPhone's first check must carry its proofs, or it answers
UNKNOWN (`authenticity`). After that first check, the engine knows the key.

## Reading a result: YES, NO or UNKNOWN

Each policy asks one question about where the device is, for example *"Is the device in
Iran?"*. `GET https://gw.octetproof.com/v1/bundle?policy=<policy>` returns it as
`question`, with `yes_is`, beside the signed bundle (the two fields aren't signed).
`yes_is` is the decision that answers YES: `deny` when the question names places a
policy excludes, `permit` when it names places it admits. Read a result like this:

1. **UNKNOWN** when `cause` is set: there's no current proof, so the question can't be
   answered. The decision is the policy's fail-closed default, not a reading of where
   the device is.
2. Otherwise **YES** when `decision == yes_is`: there's a current proof, and the device
   is in the area the policy question names.
3. Otherwise **NO**: there's a current proof, and the device is outside that area.

`cause` is one of `absence` (no proof, often no location fix yet: try again),
`stale` (the proof is older than the policy allows), `authenticity`, `unbound`,
`inconsistent` (the proof didn't pass the engine's checks), `undecidable` (the proven
area is too coarse to tell) or `other`. Treat a value you don't know as `other`.

Whether YES is good news depends on the question, so map the answer to your own action
(allow, block, step up) per policy. `question` and `yes_is` are `null` for a policy
written outside the Magistrate Studio's shape; read `decision` directly for those.

## Verifying the receipt on your server

`receipt` is the engine's signature over the decision: a compact JWS (`alg` `EdDSA`,
`typ` `octet-decision-receipt+jwt`). Forward it to your backend and decide there; the
app's own copy of `decision` is only as trustworthy as the device. On the server:

1. Fetch `https://gw.octetproof.com/.well-known/decision-receipt-jwks.json` (cache it)
   and pick the key whose `kid` matches the receipt header.
2. Check the signature with any JWS library, that `iss` is `octet-policy-engine`, and
   that `exp` hasn't passed (receipts live 300 s). Skip `exp` only when you re-check an
   archived receipt later.
3. Check the key was valid when the receipt was signed: `valid_from` ≤ `iat` <
   `valid_until` + 300 s, with no upper bound while the key has no `valid_until`.
   Archived decisions are checked the same way against
   `/.well-known/decision-receipt-key-history.json`; also check its chain: entry 0 is
   signed by its own key, and each later entry by the key before it.
4. In production, accept only `env: "release"`. `sandbox` receipts come from debug and
   simulator builds.
5. Check that `license_id` is your licence, and that `decision_ref` is one your
   backend asked for, so an older receipt can't be replayed.
6. Read `decision`, `cause` and `policy` from the receipt's claims, not from the app,
   and map them to YES / NO / UNKNOWN as above. Always read `decision` together with
   `cause`: a `deny` with a `cause` is UNKNOWN (no proof), a `deny` without one is NO. `check_policies` (the
   whole set) appears only on multi-policy checks; `policy_version` is there if you
   pin a policy version.
7. Check that `policy` (or `check_policies`) is the policy your backend asked about,
   and `policy_version` too if you pin one. A receipt for another policy is not an
   answer to your question.
8. Your backend may receive more than one receipt for the same `decision_ref`: when
   it asks again with the same `decision_ref`, the engine decides again from the same
   proofs. Keep the latest receipt for that `decision_ref`; don't count it as a new
   check.

## Obligations

A permit may carry obligations your app must honor: `.stepUpAuth`,
`.log(channel:)`, `.degrade(capability:)`, `.ttl(durationMs:)`, `.custom(name:args:)`,
or `.unknown(rawJson:)` for a forward-compatible passthrough.

## Error handling

Failures throw `PolicyError`, including `.notProvisioned`, `.licenseIdUnavailable`,
`.bundleRejected(_)` (bad signature / malformed / stale), `.noProofProduced(details:)`,
`.decideRejected(_, detail:)`, and `.decideFailed(_)`. Handle them explicitly and
fail-closed.

## Notes

- The decision is **server-authoritative** — Magistrate assembles and submits the
  attested proof, and the policy service makes the decision.
- The raw bundle-verification primitives are an internal detail of the library; the
  public surface is the `Magistrate` facade.
