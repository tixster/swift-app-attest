# swift-app-attest

[![CI](https://github.com/tixster/swift-app-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/tixster/swift-app-attest/actions/workflows/ci.yml)
[![Documentation](https://github.com/tixster/swift-app-attest/actions/workflows/docs.yml/badge.svg)](https://tixster.github.io/swift-app-attest/documentation/)
[![Swift 6.1+](https://img.shields.io/badge/Swift-6.1%2B-F05138?logo=swift&logoColor=white)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2014%2B%20%7C%20macOS%2011%2B%20%7C%20Mac%20Catalyst%2014%2B%20%7C%20tvOS%2015%2B%20%7C%20watchOS%209%2B%20%7C%20visionOS%201%2B%20%7C%20Linux-blue)](#installation)
[![SPM](https://img.shields.io/badge/SPM-compatible-brightgreen)](Package.swift)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

A Swift library for [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), covering both sides of the protocol:

- **`AppAttestClient`** — a thin async wrapper around `DCAppAttestService` for iOS, macOS, tvOS, watchOS, and visionOS apps.
- **`AppAttestServer`** — server-side verification for macOS and Linux: attestation objects, assertion objects, receipts, and the fraud-assessment (risk metric) exchange with Apple.

The server target implements every step of Apple's guides [*Validating apps that connect to your server*](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) and [*Assessing fraud risk*](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk), including the macOS access-control policy check and the `apple_validation_category_01` / `apple_bundle_version_01` authenticator-data extensions.

API documentation is published at [tixster.github.io/swift-app-attest](https://tixster.github.io/swift-app-attest/documentation/).

## What App Attest does

App Attest lets your server verify that a request came from an **unmodified copy of your app on a genuine Apple device**: the app signs requests with a key that lives in the device's Secure Enclave, and Apple certifies that the key was created there by your app. It identifies an *app install*, not a person — use it alongside (not instead of) user authentication. Typical wins: keeping bots, scrapers, and modified clients off your API.

The vocabulary, in one pass:

| Term | What it is |
|---|---|
| **Challenge** | A random one-time value your server issues. Signing it proves the response was made just now, not replayed. |
| **Key ID** | The identifier of the key pair the app created. Not a secret — the server uses it to look the key up. |
| **Attestation** | A one-time, Apple-certified proof that the key is genuine. Sent once, at *enrollment*. |
| **Assertion** | A signature over a request made with the attested key. Sent with every protected request afterwards. |
| **Client data** | The exact bytes the app signed for an assertion — typically your request body with the challenge embedded. |
| **Receipt / risk metric** | Optional: a token exchangeable with Apple for the approximate number of keys attested on that device — a fraud signal. |

And the flow, at a glance — enrollment (steps 1–3) happens once per app install; assertions (step 4) accompany protected requests from then on:

1. The app asks your server for a one-time random **challenge**.
2. The app generates a key (`generateKey`), hashes the challenge, and calls `attestKey`. It sends the **attestation object** and **key ID** to your server.
3. Your server verifies the attestation (`AttestationVerifier`) and stores the public key, counter, and receipt for that key ID.
4. For sensitive requests, the app fetches a fresh challenge, embeds it in the request (**client data**), and signs it with `generateAssertion`. Your server verifies the assertion (`AssertionVerifier`) against the stored key and counter.
5. Optionally, your server exchanges the stored receipt with Apple (`FraudAssessmentClient`) for a **risk metric** — the approximate number of keys attested on that device in the last 30 days.

## Before you start

- Add the **App Attest capability** to your app target in Xcode (the `com.apple.developer.devicecheck.appattest-environment` entitlement). Builds run from Xcode get the `development` environment; TestFlight, App Store, and enterprise builds get `production`.
- App Attest needs a **real device**: on simulators `isSupported` is `false`, so keep a fallback path.
- Enrollment needs **network access** — `attestKey` contacts Apple's servers. Generating assertions afterwards is fully local.
- Your server needs your **10-character Team ID** (Apple Developer → Membership) and the app's **bundle ID** — attestations for any other app are rejected.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/tixster/swift-app-attest.git", from: "1.1.0"),
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
let keyID = try await service.generateKey()          // persist this (not a secret — UserDefaults is fine)
let attestation = try await service.attestKey(keyID, challenge: challenge)
try await api.enroll(AttestationPayload(keyID: keyID, attestation: attestation))

// Signing a sensitive request:
let requestChallenge = try await api.fetchChallenge()
let clientData = try JSONEncoder().encode(MyRequest(action: "purchase", challenge: requestChallenge))
let assertion = try await service.generateAssertion(keyID, clientData: clientData)
try await api.send(AssertionPayload(keyID: keyID, assertion: assertion, clientData: clientData))
```

A few things to know about this code:

- **Hashing is handled for you.** The `challenge:` / `clientData:` variants compute the SHA-256 hash App Attest expects; the raw `clientDataHash:` pass-throughs are also available.
- **`MyRequest` is your own `Codable` type.** Any request body works as client data, as long as the server challenge is embedded in it. The signature covers the whole body, so neither your parameters nor the challenge can be tampered with in transit.
- **Errors are typed.** Every method is `async throws(AppAttestClientError)`, so exhaustive handling over `error.code` needs no casting. Two codes to always handle: `.serverUnavailable` is transient (Apple couldn't be reached — retry with backoff), and `.invalidKey` means the key is gone — discard the stored key ID, generate a new one, and re-attest. Key loss is normal: App Attest keys don't survive re-installs, backup restores, or device transfers.
- **The wire format is yours.** `ChallengePayload` / `AttestationPayload` / `EnrollmentPayload` / `AssertionPayload` are optional `Codable` DTOs shared with the server target (`EnrollmentPayload` adds an echoed challenge for accountless flows); use your own types if you prefer.

## Server

All verifiers share one configuration and throw typed errors — `AppAttestVerificationError` (one case per failed validation step) from the attestation and assertion verifiers, `AppAttestReceiptError` from the receipt verifier:

```swift
import AppAttestServer

let configuration = AppAttestConfiguration(
    teamIdentifier: "A1B2C3D4E5",       // Apple Developer → Membership
    bundleIdentifier: "com.example.app",
    environments: [.production]         // add .development for builds run from Xcode
)
```

### Challenges

Every verification starts from a challenge your server issued. Generate them with `AppAttestChallenge.generate()`; storing them is your job — short TTL, deleted on first use, successful or not. Two ways to find the challenge again when the client comes back:

- **Bound to a user or session** — store it under the requester's identity:

  ```swift
  // GET /app-attest/challenge
  let challenge = AppAttestChallenge.generate()
  try await cache.set("attest:\(userID)", challenge, ttl: .seconds(300))
  return ChallengePayload(challenge: challenge)  // shared Codable DTO from the library

  // POST /app-attest/enroll — consume the challenge before verifying
  guard let challenge = try await cache.getAndDelete("attest:\(userID)") else {
      throw HTTPError(.badRequest)
  }
  ```

- **Remembered by value (the echo pattern)** — for services without accounts or sessions: keep issued challenges in a store keyed by their own value, and have the client send the challenge back alongside the attestation (the shared `EnrollmentPayload` DTO exists for exactly this). Echoing is safe — the challenge isn't a secret, a tampered value fails the nonce check, and single-use consumption blocks replays. The [complete example](#complete-example) uses this pattern.

### Enrollment: verifying the attestation

```swift
// Inside your enrollment endpoint (Hummingbird shown; any framework works).
let payload = try await request.decode(as: AttestationPayload.self, context: context)
guard let challenge = try await cache.getAndDelete("attest:\(userID)") else {
    throw HTTPError(.badRequest)
}

let verifier = AttestationVerifier(configuration: configuration)
let result = try await verifier.verify(
    attestation: payload.attestation,
    keyID: payload.keyID,
    challenge: challenge  // the raw challenge you issued, now consumed
)

// Persist, keyed by the key ID (one row per app install — App Attest has no
// device ID or user identity; the attested key itself plays that role). If your
// service has accounts, also associate the row with the authenticated user:
// result.publicKeyX963Representation, result.signCount, result.receipt, result.environment
```

### Protected requests: verifying assertions

```swift
// Inside a protected endpoint: decode the payload, look up the key it names.
// `storedKey` comes from your database (saved at enrollment); `challenge`
// was issued and cached per request, same flow as during enrollment.
let payload = try await request.decode(as: AssertionPayload.self, context: context)
let storedKey = try await keys.find(payload.keyID)  // public key + counter from enrollment

let verifier = AssertionVerifier(configuration: configuration)
let result = try verifier.verify(
    assertion: payload.assertion,
    clientData: payload.clientData,
    publicKeyX963Representation: storedKey.publicKey,
    previousSignCount: storedKey.signCount,
    expectedChallenge: challenge,
    challengeExtractor: { data in
        try JSONDecoder().decode(MyRequest.self, from: data).challenge
    }
)
storedKey.signCount = result.signCount  // persist the new counter
```

`clientData` is opaque to the library — it's hashed, never parsed, so any format works. The `challengeExtractor` is how you tell the verifier where *your* format keeps the challenge (any field name, JSON or not), which gives the challenge check three modes:

- `expectedChallenge` + `challengeExtractor` — structured body, the extractor pulls the challenge out;
- `expectedChallenge` only — the client signed the bare challenge (`clientData == challenge`);
- neither — the built-in check is skipped and you validate the challenge yourself (as the echo pattern in the complete example does, by consuming it from a store by value).

One rule when designing the wire format: ship the signed bytes verbatim (that's what `AssertionPayload.clientData` is) and decode your business data *from those bytes*. Don't flatten the signed fields into the outer request — JSON isn't canonical, so re-encoding them on the server yields different bytes and the signature check fails.

**Headers instead of an envelope.** The `AssertionPayload` JSON envelope is optional — the verifier only needs the bytes. An alternative that avoids double-encoding: put the key ID and assertion in headers and make the request body *be* the signed client data:

```text
POST /purchase HTTP/1.1
X-App-Attest-Key-Id: SqW5C1zi…
X-App-Attest-Assertion: omlzaWduYXR1cmX…
Content-Type: application/json

{"action":"purchase","challenge":"aFMwd0…"}
```

The client signs the encoded body, attaches the two headers, and ships the body untouched:

```swift
let body = try JSONEncoder().encode(MyRequest(action: "purchase", challenge: requestChallenge))
let assertion = try await service.generateAssertion(keyID, clientData: body)

var urlRequest = URLRequest(url: purchaseURL)
urlRequest.httpMethod = "POST"
urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
urlRequest.setValue(keyID.base64EncodedString, forHTTPHeaderField: "X-App-Attest-Key-Id")
urlRequest.setValue(assertion.base64EncodedString(), forHTTPHeaderField: "X-App-Attest-Assertion")
urlRequest.httpBody = body
let (data, _) = try await URLSession.shared.data(for: urlRequest)
```

The server reads the headers, verifies against the raw body, and decodes the order from those same bytes (Hummingbird shown; any framework works):

```swift
// Custom header names as HTTPField.Name constants:
extension HTTPField.Name {
    static let appAttestKeyID = Self("X-App-Attest-Key-Id")!
    static let appAttestAssertion = Self("X-App-Attest-Assertion")!
}

router.post("purchase") { request, context -> HTTPResponse.Status in
    guard
        let keyIDHeader = request.headers[.appAttestKeyID],
        let assertion = request.headers[.appAttestAssertion].flatMap({ Data(base64Encoded: $0) })
    else { throw HTTPError(.unauthorized) }
    let keyID = AppAttestKeyID(base64EncodedString: keyIDHeader)

    // The body bytes exactly as received — never re-encoded.
    let rawBody = Data(buffer: try await request.body.collect(upTo: 64 * 1024))

    let storedKey = try await keys.find(keyID)  // public key + counter from enrollment
    let result = try verifier.verify(
        assertion: assertion,
        clientData: rawBody,
        publicKeyX963Representation: storedKey.publicKey,
        previousSignCount: storedKey.signCount,
        expectedChallenge: challenge,  // issued and cached per request, as above
        challengeExtractor: { try JSONDecoder().decode(MyRequest.self, from: $0).challenge }
    )
    storedKey.signCount = result.signCount  // persist the new counter

    let order = try JSONDecoder().decode(MyRequest.self, from: rawBody)
    // act on `order`
    return .ok
}
```

Two limits. The challenge stays *inside* the signed bytes — an unsigned header isn't covered by the signature, so a captured-but-undelivered request could be replayed later under a fresh challenge. And attestation objects run to several kilobytes (certificate chain plus receipt), too big for headers — keep *enrollment* in the request body. Details and a bodyless-request variant: [Verifying assertions](https://tixster.github.io/swift-app-attest/documentation/appattestserver/verifyingassertions).

**When to require assertions.** Protect the endpoints where forgery hurts — purchases, premium content, account changes; ordinary traffic doesn't need assertions. Each protected call costs one challenge fetch, and two patterns cheapen that: return the **next challenge** in every protected response so the extra round-trip disappears, or require one assertion to mint a **short-lived session token** and protect everything else with that token. Either way, generate assertions **sequentially** — the key's counter must strictly increase, so two signed requests racing each other can arrive out of order and fail the counter check.

### Receipts and fraud assessment

This part is optional — attestations and assertions work without ever touching receipts. Use it when you want Apple's fraud signal:

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
    credentials: try DeviceCheckCredentials(
        keyIdentifier: "ABC123DEFG",     // key from Apple Developer portal (DeviceCheck enabled)
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

A high risk metric can indicate a compromised device serving many copies of your app. The metric also grows on re-installs and device transfers, so tune thresholds to your traffic.

## Complete example

The snippets above, assembled into working shape — with no sessions or accounts: challenges are remembered *by value* and echoed back by the client in the library's `EnrollmentPayload` (see [Challenges](#challenges)). Only `api` and `fulfil(_:)` are your app's own pieces; everything else is real library API. `PurchaseRequest` appears in both blocks — in a real project, share it through a common module.

<details>
<summary><strong>Client: an enrollment + signing manager</strong></summary>

```swift
import AppAttestClient
import Foundation

struct PurchaseRequest: Codable {
    var productID: String
    var challenge = Data()  // filled in right before signing
}

/// Owns the App Attest key: enrolls lazily, signs requests, recovers from key loss.
final class AppAttestManager {
    private let service = AppAttestService.shared
    private let api: BackendAPI  // your networking layer

    // The key ID isn't a secret (the private key never leaves the Secure
    // Enclave), so UserDefaults is fine.
    private var keyID: AppAttestKeyID? {
        get { UserDefaults.standard.string(forKey: "appAttestKeyID")
                .map(AppAttestKeyID.init(base64EncodedString:)) }
        set { UserDefaults.standard.set(newValue?.base64EncodedString, forKey: "appAttestKeyID") }
    }

    init(api: BackendAPI) { self.api = api }

    /// Returns the enrolled key ID, running enrollment first if needed.
    func ensureEnrolled() async throws -> AppAttestKeyID {
        guard service.isSupported else {
            throw BackendAPI.Error.appAttestUnavailable  // simulator/old device: fall back
        }
        if let keyID { return keyID }

        let challenge = try await api.fetchChallenge()
        let newKeyID = try await service.generateKey()
        let attestation = try await service.attestKey(newKeyID, challenge: challenge)
        try await api.enroll(EnrollmentPayload(
            challenge: challenge,  // echoed back so the server can look it up
            keyID: newKeyID,
            attestation: attestation
        ))
        keyID = newKeyID  // persist only after the server accepted the enrollment
        return newKeyID
    }

    /// Signs and sends a protected request, re-enrolling transparently on key loss.
    func send(_ request: PurchaseRequest) async throws -> BackendAPI.Response {
        var request = request
        request.challenge = try await api.fetchChallenge()
        let clientData = try JSONEncoder().encode(request)

        do {
            let keyID = try await ensureEnrolled()
            let assertion = try await service.generateAssertion(keyID, clientData: clientData)
            return try await api.send(
                AssertionPayload(keyID: keyID, assertion: assertion, clientData: clientData)
            )
        } catch let error as AppAttestClientError where error.code == .invalidKey {
            // The key didn't survive a re-install/restore/transfer. Normal:
            // drop it and enroll from scratch. (Cap retries in production.)
            keyID = nil
            return try await send(request)
        }
    }
}
```

</details>

<details>
<summary><strong>Server: challenge, enrollment, and a protected endpoint (Hummingbird)</strong></summary>

```swift
import AppAttestServer
import Hummingbird

let configuration = AppAttestConfiguration(
    teamIdentifier: "A1B2C3D4E5",
    bundleIdentifier: "com.example.app",
    environments: [.production]
)
let attestations = AttestationVerifier(configuration: configuration)
let assertions = AssertionVerifier(configuration: configuration)

// PurchaseRequest is the app-defined type from the client block above;
// ChallengePayload / EnrollmentPayload / AssertionPayload come from the library.
struct PurchaseRequest: Codable {
    var productID: String
    var challenge = Data()
}

// Let Hummingbird encode the library's ChallengePayload as a JSON response.
extension ChallengePayload: @retroactive ResponseEncodable {}

// In-memory storage to keep the example self-contained; use your database.
// No sessions or accounts: issued challenges are remembered *by value* and
// consumed on first use (the echo pattern). Add a TTL in production so the
// set of never-used challenges doesn't grow forever.
actor AttestedKeyStore {
    struct Record { var publicKey: Data; var signCount: UInt32; var receipt: Data }
    private var records: [Data: Record] = [:]  // keyed by raw key ID
    private var challenges: Set<Data> = []     // issued, not yet used

    func issueChallenge() -> Data {
        let challenge = AppAttestChallenge.generate()
        challenges.insert(challenge)
        return challenge
    }
    /// True when this challenge was issued by us and hasn't been used yet.
    func consumeChallenge(_ challenge: Data) -> Bool {
        challenges.remove(challenge) != nil
    }
    func find(_ keyID: AppAttestKeyID) -> Record? {
        keyID.rawBytes.flatMap { records[$0] }
    }
    func save(_ keyID: AppAttestKeyID, _ record: Record) {
        if let raw = keyID.rawBytes { records[raw] = record }
    }
}
let store = AttestedKeyStore()

let router = Router()

// 1. Both enrollment and protected requests start by fetching a challenge.
router.get("app-attest/challenge") { _, _ -> ChallengePayload in
    ChallengePayload(challenge: await store.issueChallenge())
}

// 2. Enrollment: the client echoes the challenge next to the attestation.
//    Echoing is safe — the challenge isn't a secret. A tampered one fails
//    the attestation's nonce check, an unknown one isn't in the store, and
//    a reused one was already consumed.
router.post("app-attest/enroll") { request, context -> HTTPResponse.Status in
    let enroll = try await request.decode(as: EnrollmentPayload.self, context: context)
    guard await store.consumeChallenge(enroll.challenge) else {
        throw HTTPError(.badRequest, message: "unknown or already-used challenge")
    }
    let result = try await attestations.verify(
        attestation: enroll.attestation,
        keyID: enroll.keyID,
        challenge: enroll.challenge
    )
    await store.save(enroll.keyID, .init(
        publicKey: result.publicKeyX963Representation,
        signCount: result.signCount,
        receipt: result.receipt
    ))
    return .ok
}

// 3. A protected endpoint. No separate echo here: the challenge already
//    travels inside the signed client data.
router.post("purchase") { request, context -> HTTPResponse.Status in
    let payload = try await request.decode(as: AssertionPayload.self, context: context)
    let order = try JSONDecoder().decode(PurchaseRequest.self, from: payload.clientData)
    guard
        var record = await store.find(payload.keyID),
        await store.consumeChallenge(order.challenge)
    else {
        throw HTTPError(.unauthorized)  // same response as a bad signature: no key enumeration
    }

    let verified: VerifiedAssertion
    do {
        verified = try assertions.verify(
            assertion: payload.assertion,
            clientData: payload.clientData,
            publicKeyX963Representation: record.publicKey,
            previousSignCount: record.signCount
            // No expectedChallenge here: consuming the challenge from the
            // store already validated it, and the signature covers the exact
            // bytes it's embedded in.
        )
    } catch {
        context.logger.info("assertion rejected: \(error)")
        throw HTTPError(.unauthorized)  // uniform failure response
    }
    record.signCount = verified.signCount  // persist the new counter
    await store.save(payload.keyID, record)

    // Safe to act on the order now — the signature covered every byte of it.
    try await fulfil(order.productID)  // fulfil(_:) is your own business logic
    return .ok
}

let app = Application(router: router)
try await app.runService()
```

</details>

## Security notes

- **Challenges must be single-use.** Generate a random value per enrollment/request (`AppAttestChallenge.generate()`), remember it server-side, and invalidate it after one verification attempt.
- **Persist and enforce the counter.** Reject assertions whose counter isn't strictly greater than the stored one (the library checks this for you when you pass `previousSignCount`). Gaps like 1, 3, 7 are normal — an assertion that never reached you still increments the device counter — so never require consecutive values.
- **One key, one user** (if you bind keys to accounts). Reject enrollment if the attested public key is already associated with a different account. Accountless services skip this and instead watch per-key behavior and the fraud-risk metric.
- **Keep environments separate.** Development attestations, receipts, and metrics are invalid in production and vice versa.
- **Attest keys again on `invalidKey`.** Client-side key loss is normal (re-install, restore, transfer); treat re-attestation as a regular flow.
- **Answer all assertion failures alike.** Return the same generic `401` whether the key is unknown or the signature is bad, so attackers can't enumerate enrolled key IDs.

## Testing

The test suite builds synthetic attestations, assertions, and CMS-signed receipts with a throwaway CA chain (the verifiers accept trust-root overrides via `AppAttestConfiguration`), so it runs fully offline:

```bash
swift test
```

## License

MIT — see [LICENSE](LICENSE).
