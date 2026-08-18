# Verifying Assertions

Validate the assertions a client attaches to sensitive requests.

## Overview

After enrollment, require clients to accompany sensitive requests with an
assertion: the app packages the request as *client data* (embedding a fresh
server challenge), hashes it, and signs it with the attested key via
`DCAppAttestService.generateAssertion(_:clientDataHash:)`.

Unlike attestation, this involves no round-trip to Apple: the app signs
locally, and verification happens entirely on your server — so the
per-request overhead is one challenge fetch plus one signature check.

Your server verifies the assertion with ``AssertionVerifier``, using the
public key and counter stored at enrollment:

```swift
// Decode the request body your app sent — for example, the shared
// `AssertionPayload` DTO — and look up the key it names:
let payload = try req.content.decode(AssertionPayload.self)
let storedKey = try await keys.find(payload.keyID)

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
storedKey.signCount = result.signCount
```

The verifier checks the ECDSA signature over
`SHA256(authenticatorData || SHA256(clientData))`, your App ID's hash, that
the counter strictly increased, and — when you pass `expectedChallenge` —
that the challenge embedded in the client data matches.

## The counter

Every successful verification returns a new ``VerifiedAssertion/signCount``.
Persist it: the next assertion for the same key must carry a greater value,
which prevents replaying captured assertions.

## Client data formats

App Attest doesn't prescribe a client-data format. Two common options:

- **Bare challenge** — the client signs the challenge itself. Pass the
  challenge as both `clientData` and `expectedChallenge` and omit the
  extractor.
- **Structured request** — the client signs the whole request body with the
  challenge embedded. Pass a `challengeExtractor` that pulls the challenge out
  of your format.
