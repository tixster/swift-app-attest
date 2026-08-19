# Verifying Assertions

Validate the assertions a client attaches to sensitive requests.

## Overview

After enrollment, require clients to accompany sensitive requests with an
assertion: the app packages the request as *client data* (embedding a fresh
server challenge), hashes it, and signs it with the attested key via
`DCAppAttestService.generateAssertion(_:clientDataHash:)`.

Unlike attestation, this involves no round-trip to Apple: the app signs
locally, and verification happens entirely on your server — the per-request
overhead is one challenge fetch plus one signature check.

## Verifying

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
bytes — without one, a captured assertion can be replayed later.

One rule when designing the wire format: ship the signed bytes verbatim, as
an opaque blob inside an envelope of key ID and assertion (`AssertionPayload`
is exactly that). Resist flattening the signed fields into the outer request
body — the signature covers an *exact byte sequence*, and JSON is not
canonical, so re-encoding decoded fields on the server produces different
bytes (key order, whitespace, number formatting) and the signature check
fails even though the data is "the same". Verify against the shipped bytes
and decode your business data from those same bytes, never from a re-encoded
copy. The upside of this design: everything embedded in the blob — your
parameters and the challenge alike — is tamper-proof in transit.

## Transport variants

The verifier needs three values — the key ID, the assertion object, and the
client data — and doesn't care how they travel. Pick whichever shape fits
your API; the only firm rule is the one above: the client-data bytes must
arrive verbatim.

**JSON envelope** — the shared `AssertionPayload` DTO used throughout these
docs: all three values in one JSON body, the signed bytes riding inside it as
a Base64 string. Simplest to adopt; the cost is double encoding — your
request body travels inside the envelope's JSON.

**Headers plus raw body** — carry the proof in HTTP headers and make the
body *be* the client data, byte for byte:

```text
POST /purchase HTTP/1.1
X-App-Attest-Key-Id: SqW5C1zi…
X-App-Attest-Assertion: omlzaWduYXR1cmX…
Content-Type: application/json

{"productID":"coins.large","challenge":"aFMwd0…"}
```

The client signs the encoded body and ships it untouched:

```swift
let body = try JSONEncoder().encode(order)  // challenge embedded, as always
let assertion = try await service.generateAssertion(keyID, clientData: body)

var request = URLRequest(url: purchaseURL)
request.httpMethod = "POST"
request.setValue(keyID.base64EncodedString, forHTTPHeaderField: "X-App-Attest-Key-Id")
request.setValue(assertion.base64EncodedString(), forHTTPHeaderField: "X-App-Attest-Assertion")
request.httpBody = body
```

The server verifies against the raw body it received and decodes the order
from those same bytes (header and body APIs vary by framework):

```swift
guard
    let keyIDHeader = headers["X-App-Attest-Key-Id"],
    let assertion = Data(base64Encoded: headers["X-App-Attest-Assertion"] ?? "")
else { throw HTTPError(.unauthorized) }
let keyID = AppAttestKeyID(base64EncodedString: keyIDHeader)
let body: Data = ...  // the raw request body, collected — never re-encoded

let result = try verifier.verify(
    assertion: assertion,
    clientData: body,
    publicKeyX963Representation: storedKey.publicKey,
    previousSignCount: storedKey.signCount,
    expectedChallenge: challenge,
    challengeExtractor: { try JSONDecoder().decode(PurchaseRequest.self, from: $0).challenge }
)
let order = try JSONDecoder().decode(PurchaseRequest.self, from: body)
```

This keeps the endpoint's body a plain document — no Base64 wrapping, natural
content types, any format. Size-wise it's a good fit too: assertion objects
are a few hundred bytes, comfortably inside common header limits. Attestation
objects are not — several kilobytes of certificate chain and receipt — so
keep *enrollment* in the request body.

**Bodyless requests** — when a protected call carries no body at all, use
the bare-challenge mode: the client signs the challenge itself
(`clientData == challenge`), and both the challenge and the assertion travel
as headers. That's safe precisely because the challenge header *is* the
signed bytes.

One thing must never move to an unsigned header: the challenge of a request
that has a body. The signature wouldn't cover it, so an attacker who captured
a signed request that never reached you could replay it later under a freshly
fetched challenge — the counter check alone can't catch an assertion your
server has never seen. Keep the challenge inside the bytes the client signs.

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
