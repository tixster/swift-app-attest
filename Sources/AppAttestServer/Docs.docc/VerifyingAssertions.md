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
// `AssertionPayload` DTO (Hummingbird shown) — and look up the key it names:
let payload = try await request.decode(as: AssertionPayload.self, context: context)
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
Persist it: the next assertion for the same key must carry a *greater* value,
which prevents replaying captured assertions. Gaps are normal — the device
increments the counter on every `generateAssertion` call, including ones
whose requests never reached you — so expect sequences like 1, 3, 7 and
never require consecutive values.

A consequence: clients should generate and send assertions *sequentially*.
Two assertions racing each other can arrive out of order, and the
later-signed one will fail the counter check.

## Reducing the per-request cost

Each protected request costs one challenge fetch. Two common patterns remove
that overhead:

- **Challenge ahead**: return the next challenge in every protected response,
  so the client always has one ready.
- **Session minting**: require a single assertion to issue a short-lived
  session token, and protect subsequent requests with that token. App Attest
  then guards the token grant rather than every call.

## Client data formats

Client data is opaque to the library on both sides: the client hashes the
bytes to sign them, and the verifier hashes the same bytes to check the
signature — neither ever parses them. Its structure, and where the challenge
lives inside it, is a contract between your app and your server. The
`challengeExtractor` closure is the bridge between that contract and the
built-in challenge check, which gives you three modes:

- **Bare challenge** — the client signs the challenge bytes themselves.
  Pass the challenge as `expectedChallenge` and omit the extractor;
  `clientData` is compared to it directly.
- **Structured request** — the client signs a request body with the
  challenge embedded somewhere. Pass an extractor that pulls it out.
- **Manual** — omit `expectedChallenge`; the library skips the challenge
  step and you validate it yourself around `verify`.

In the structured case the field name and encoding are entirely yours — the
extractor can decode anything:

```swift
// A nested JSON field named however you like:
challengeExtractor: { try JSONDecoder().decode(Envelope.self, from: $0).meta.nonce }

// Not JSON at all — a binary layout with the challenge in the last 32 bytes:
challengeExtractor: { $0.suffix(32) }
```

Whatever the format, embed *some* server-issued challenge in the signed
bytes — without one, a captured assertion can be replayed later. And because
the signature covers all of `clientData`, everything embedded in it — your
parameters and the challenge alike — is tamper-proof in transit.
