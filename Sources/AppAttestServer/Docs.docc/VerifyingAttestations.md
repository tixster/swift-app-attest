# Verifying Attestations

Validate the attestation object a client sends at enrollment and store the attested key.

## Overview

Enrollment is a one-time step per app install. It starts on the client: the
app asks your server for a one-time challenge, generates an App Attest key,
and calls `DCAppAttestService.attestKey(_:clientDataHash:)` with the SHA-256
hash of the challenge. It then sends the resulting attestation object and the
key identifier to your server, where ``AttestationVerifier`` validates them
and hands you the key material to persist.

Expect re-enrollment as a normal event: App Attest keys don't survive app
re-installs, backup restores, or device transfers, so the same physical
device will eventually return with a brand-new key.

## Issuing challenges

Every enrollment starts from a challenge your server issued. Challenges must
be unpredictable and single-use: generate one with
``AppAttestChallenge/generate(byteCount:)``, remember it server-side with a
short TTL, and invalidate it after the first verification attempt —
successful or not.

Two ways to find the challenge again when the client comes back:

- **Bound to a user or session** — store it under the requester's identity
  and look it up when the enrollment request arrives.
- **Remembered by value** — for services without accounts or sessions, keep
  issued challenges in a store keyed by their own value and have the client
  echo the challenge back alongside the attestation (the shared
  `EnrollmentPayload` DTO carries exactly that trio: challenge, key ID,
  attestation). Echoing is safe: the challenge isn't a secret, a tampered
  value fails the nonce check, and single-use consumption blocks replays.

## Verifying

```swift
let configuration = AppAttestConfiguration(
    teamIdentifier: "A1B2C3D4E5",
    bundleIdentifier: "com.example.app",
    environments: [.production]
)

// Decode the request body your app sent — for example, the shared
// `AttestationPayload` DTO (Hummingbird shown; any framework works):
let payload = try await request.decode(as: AttestationPayload.self, context: context)

let verifier = AttestationVerifier(configuration: configuration)
let result = try await verifier.verify(
    attestation: payload.attestation,
    keyID: payload.keyID,
    challenge: challenge
)
```

The verifier performs Apple's full validation procedure: it checks the
certificate chain against the App Attest root CA, recomputes and compares the
nonce, matches the key identifier against the certificate's public key,
verifies your App ID's hash, requires a zero counter, checks the environment
AAGUID, compares the credential ID, and — when the credential certificate
carries the macOS access-control policy extension — verifies that the key is
protected by SIP and Full Security mode.

## Storing the result

Persist these values, keyed by the key identifier. App Attest exposes no
device ID or user identity — the attested key itself identifies one app
install on one device. If your service has accounts, also associate the row
with the authenticated user and expect one row per device a user enrolls
from; accountless services simply treat the key as an anonymous install:

- ``VerifiedAttestation/publicKeyX963Representation`` (or the
  ``VerifiedAttestation/publicKey``) — needed to verify assertions.
- ``VerifiedAttestation/signCount`` — the starting counter value.
- ``VerifiedAttestation/receipt`` — the input for <doc:AssessingFraudRisk>.
- ``VerifiedAttestation/environment`` — keep development and production data
  apart.

As an added replay protection when you bind keys to accounts, reject
enrollment when the public key is already associated with another user.
