# ``AppAttestClient``

Generate App Attest keys, attestations, and assertions on Apple devices.

## Overview

This module is the client half of the protocol: a thin async wrapper around
`DCAppAttestService` with typed errors and the shared key-identifier type, so
the values you send line up with what the `AppAttestServer` verifiers expect.

The flow has two parts. Enrollment runs once per app install:

```swift
let service = AppAttestService.shared
guard service.isSupported else { /* simulators and some devices: fall back */ }

let challenge = try await api.fetchChallenge()
let keyID = try await service.generateKey()
let attestation = try await service.attestKey(keyID, challenge: challenge)
try await api.enroll(AttestationPayload(keyID: keyID, attestation: attestation))
```

Signing accompanies every protected request afterwards:

```swift
let requestChallenge = try await api.fetchChallenge()
let clientData = try JSONEncoder().encode(
    MyRequest(action: "purchase", challenge: requestChallenge)
)
let assertion = try await service.generateAssertion(keyID, clientData: clientData)
try await api.send(AssertionPayload(keyID: keyID, assertion: assertion, clientData: clientData))
```

Persist the key identifier (it isn't a secret) and treat
``AppAttestClientError/Code/invalidKey`` as a normal event: App Attest keys
don't survive re-installs, backup restores, or device transfers, so discard
the stored identifier, generate a new key, and enroll again.

The shared types — `AppAttestKeyID` and the optional wire-format DTOs
(`AttestationPayload`, `ChallengePayload`, `EnrollmentPayload`,
`AssertionPayload`) — live in the `AppAttestCore` module and are re-exported
here, so `import AppAttestClient` is all you need.

## Topics

### Essentials

- ``AppAttestService``

### Errors

- ``AppAttestClientError``
