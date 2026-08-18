# swift-app-attest

[![CI](https://github.com/tixster/swift-app-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/tixster/swift-app-attest/actions/workflows/ci.yml)
[![Documentation](https://github.com/tixster/swift-app-attest/actions/workflows/docs.yml/badge.svg)](https://tixster.github.io/swift-app-attest/documentation/)
[![Swift 6.1+](https://img.shields.io/badge/Swift-6.1%2B-F05138?logo=swift&logoColor=white)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2014%2B%20%7C%20macOS%2011%2B%20%7C%20tvOS%2015%2B%20%7C%20watchOS%209%2B%20%7C%20visionOS%201%2B%20%7C%20Linux-blue)](#installation)
[![SPM](https://img.shields.io/badge/SPM-compatible-brightgreen)](Package.swift)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

A Swift library for [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), covering both sides of the protocol:

- **`AppAttestClient`** — a thin async wrapper around `DCAppAttestService` for iOS, macOS, tvOS, watchOS, and visionOS apps.
- **`AppAttestServer`** — server-side verification for macOS and Linux: attestation objects, assertion objects, receipts, and the fraud-assessment (risk metric) exchange with Apple.

The server target implements every step of Apple's guides [*Validating apps that connect to your server*](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) and [*Assessing fraud risk*](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk), including the macOS access-control policy check and the `apple_validation_category_01` / `apple_bundle_version_01` authenticator-data extensions.

API documentation is published at [tixster.github.io/swift-app-attest](https://tixster.github.io/swift-app-attest/documentation/).

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/tixster/swift-app-attest.git", from: "0.1.0"),
],
targets: [
    // In your app target:
    .target(name: "MyApp", dependencies: [
        .product(name: "AppAttestClient", package: "swift-app-attest"),
    ]),
    // In your server target:
    .target(name: "MyServer", dependencies: [
        .product(name: "AppAttestServer", package: "swift-app-attest"),
    ]),
]
```

The server product depends on [swift-crypto](https://github.com/apple/swift-crypto), [swift-certificates](https://github.com/apple/swift-certificates), and [swift-asn1](https://github.com/apple/swift-asn1), and builds on Linux. The client product has no dependencies beyond DeviceCheck.

## The flow at a glance

1. The app asks your server for a one-time random **challenge**.
2. The app generates a key (`generateKey`), hashes the challenge, and calls `attestKey`. It sends the **attestation object** and **key ID** to your server.
3. Your server verifies the attestation (`AttestationVerifier`) and stores the public key, counter, and receipt for that user/device.
4. For sensitive requests, the app fetches a fresh challenge, embeds it in the request (**client data**), and signs it with `generateAssertion`. Your server verifies the assertion (`AssertionVerifier`) against the stored key and counter.
5. Optionally, your server exchanges the stored receipt with Apple (`FraudAssessmentClient`) to obtain a **risk metric** — the approximate number of keys attested on that device in the last 30 days.

## Client

```swift
import AppAttestClient

let service = AppAttestService.shared
guard service.isSupported else {
    // Simulators and some devices don't support App Attest; fall back.
    return
}

// Enrollment (once per install):
let challenge = try await api.fetchChallenge()
let keyID = try await service.generateKey()          // persist this
let attestation = try await service.attestKey(keyID, challenge: challenge)
try await api.enroll(AttestationPayload(keyID: keyID, attestation: attestation))

// Signing a sensitive request:
let requestChallenge = try await api.fetchChallenge()
let clientData = try JSONEncoder().encode(MyRequest(action: "purchase", challenge: requestChallenge))
let assertion = try await service.generateAssertion(keyID, clientData: clientData)
try await api.send(AssertionPayload(keyID: keyID, assertion: assertion, clientData: clientData))
```

The `challenge:` / `clientData:` variants hash with SHA-256 for you; the raw `clientDataHash:` pass-throughs are also available.

All methods throw typed errors (`async throws(AppAttestClientError)`), so exhaustive handling over `error.code` needs no casting. On `.invalidKey`, discard the stored key ID, generate a new key, and re-attest — App Attest keys don't survive re-installs, backup restores, or device transfers.

`AttestationPayload` / `AssertionPayload` are optional `Codable` DTOs shared with the server target; use your own wire format if you prefer.

## Server

The verifiers throw typed errors: `AttestationVerifier` and `AssertionVerifier` throw `AppAttestVerificationError` (one case per failed validation step), and `ReceiptVerifier` throws `AppAttestReceiptError`.

### Issuing challenges

Generate challenges with `AppAttestChallenge.generate()` and store them yourself — with a short TTL, bound to the user or session, and deleted on first use:

```swift
// GET /app-attest/challenge
let challenge = AppAttestChallenge.generate()
try await cache.set("attest:\(userID)", challenge, ttl: .seconds(300))
return ChallengeResponse(challenge: challenge)

// POST /app-attest/enroll — consume the challenge before verifying
guard let challenge = try await cache.getAndDelete("attest:\(userID)") else {
    throw Abort(.badRequest)
}
```

### Verifying an attestation

```swift
import AppAttestServer

let configuration = AppAttestConfiguration(
    teamIdentifier: "A1B2C3D4E5",
    bundleIdentifier: "com.example.app",
    environments: [.production]  // add .development for Xcode builds
)

// Inside your enrollment endpoint (Vapor shown; any framework works).
// AttestationPayload is the shared Codable DTO the client example sends.
let payload = try req.content.decode(AttestationPayload.self)
guard let storedChallenge = try await cache.getAndDelete("attest:\(userID)") else {
    throw Abort(.badRequest)
}

let verifier = AttestationVerifier(configuration: configuration)
let result = try await verifier.verify(
    attestation: payload.attestation,
    keyID: payload.keyID,
    challenge: storedChallenge  // the raw challenge you issued, now single-use
)

// Persist for this user + device:
// result.publicKeyX963Representation, result.signCount, result.receipt, result.environment
```

### Verifying an assertion

```swift
// Inside a protected endpoint: decode the payload, look up the key it names.
let payload = try req.content.decode(AssertionPayload.self)
let storedKey = try await keys.find(payload.keyID)  // public key + counter from enrollment

let verifier = AssertionVerifier(configuration: configuration)
let result = try verifier.verify(
    assertion: payload.assertion,
    clientData: payload.clientData,
    publicKeyX963Representation: storedKey.publicKey,
    previousSignCount: storedKey.signCount,
    expectedChallenge: storedChallenge,
    challengeExtractor: { data in
        try JSONDecoder().decode(MyRequest.self, from: data).challenge
    }
)
storedKey.signCount = result.signCount  // persist the new counter
```

If the client signs the bare challenge (`clientData == challenge`), omit `challengeExtractor`.

### Receipts and fraud assessment

```swift
// Verify the receipt that came with the attestation (Apple recommends
// rejecting receipts older than 5 minutes at enrollment):
let receiptVerifier = ReceiptVerifier(configuration: configuration)
let receipt = try await receiptVerifier.verify(
    receipt: result.receipt,
    expectedPublicKey: result.publicKey,
    maximumCreationAge: 300
)

// Later: exchange the receipt for a fresh one carrying the risk metric.
let client = FraudAssessmentClient(
    environment: result.environment,
    credentials: try AppStoreConnectCredentials(
        keyIdentifier: "ABC123DEFG",     // App Store Connect key ID (DeviceCheck enabled)
        teamIdentifier: "A1B2C3D4E5",
        privateKeyPEM: p8FileContents
    )
)

do {
    let refreshedData = try await client.refreshReceipt(storedReceipt)
    let refreshed = try await receiptVerifier.verify(
        receipt: refreshedData,
        expectedPublicKey: storedPublicKey
    )
    print("Risk metric:", refreshed.riskMetric ?? 0)
    // Store refreshedData in place of the old receipt; refresh again after
    // refreshed.notBefore and before refreshed.expirationTime.
} catch FraudAssessmentError.notModified {
    // Requested before the receipt's "Not Before" date — try again later.
}
```

A high risk metric can indicate a compromised device serving many copies of your app. Note the metric also grows on re-installs and device transfers, so tune thresholds to your traffic.

## Security notes

- **Challenges must be single-use.** Generate a random value per enrollment/request (`AppAttestChallenge.generate()`), remember it server-side, and invalidate it after one verification attempt.
- **Persist and enforce the counter.** Reject assertions whose counter isn't strictly greater than the stored one (the library checks this for you when you pass `previousSignCount`).
- **One key, one user.** Reject enrollment if the attested public key is already associated with a different account.
- **Keep environments separate.** Development attestations, receipts, and metrics are invalid in production and vice versa.
- **Attest keys again on `invalidKey`.** Client-side key loss is normal (re-install, restore, transfer); treat re-attestation as a regular flow.

## Testing

The test suite builds synthetic attestations, assertions, and CMS-signed receipts with a throwaway CA chain (the verifiers accept trust-root overrides via `AppAttestConfiguration`), so it runs fully offline:

```bash
swift test
```

## License

MIT — see [LICENSE](LICENSE).
