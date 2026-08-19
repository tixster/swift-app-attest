import Foundation

/// A ready-made payload for sending an attestation object from the client to
/// your server.
///
/// Using this type is optional — App Attest doesn't prescribe a wire format —
/// but sharing it between the client and server targets keeps both sides in
/// sync. `Data` values are encoded as Base64 strings by `JSONEncoder`.
public struct AttestationPayload: Sendable, Hashable, Codable {
    /// The identifier of the attested key.
    public var keyID: AppAttestKeyID

    /// The CBOR-encoded attestation object produced by
    /// `DCAppAttestService.attestKey(_:clientDataHash:)`.
    public var attestation: Data

    /// Creates an attestation payload.
    public init(keyID: AppAttestKeyID, attestation: Data) {
        self.keyID = keyID
        self.attestation = attestation
    }
}

/// A ready-made payload for handing a server-issued challenge to the client.
///
/// The only payload that travels server → client: your challenge endpoint
/// returns it, and the client feeds the challenge into `DCAppAttestService`
/// calls or embeds it in client data.
public struct ChallengePayload: Sendable, Hashable, Codable {
    /// The server-issued challenge. Encodes as a Base64 string in JSON.
    public var challenge: Data

    /// Creates a challenge payload.
    public init(challenge: Data) {
        self.challenge = challenge
    }
}

/// A ready-made enrollment payload for the challenge-echo pattern: the client
/// sends the server-issued challenge back verbatim alongside the attestation,
/// so the server can look the challenge up by value instead of binding it to
/// a user or session.
///
/// If you bind challenges to authenticated users or sessions instead, the
/// smaller ``AttestationPayload`` is all you need.
public struct EnrollmentPayload: Sendable, Hashable, Codable {
    /// The server-issued challenge, echoed back verbatim.
    public var challenge: Data

    /// The identifier of the attested key.
    public var keyID: AppAttestKeyID

    /// The CBOR-encoded attestation object produced by
    /// `DCAppAttestService.attestKey(_:clientDataHash:)`.
    public var attestation: Data

    /// Creates an enrollment payload.
    public init(challenge: Data, keyID: AppAttestKeyID, attestation: Data) {
        self.challenge = challenge
        self.keyID = keyID
        self.attestation = attestation
    }

    /// Creates an enrollment payload by wrapping an ``AttestationPayload``.
    public init(challenge: Data, payload: AttestationPayload) {
        self.init(challenge: challenge, keyID: payload.keyID, attestation: payload.attestation)
    }
}

/// A ready-made payload for sending an assertion object from the client to
/// your server.
///
/// Using this type is optional — App Attest doesn't prescribe a wire format —
/// but sharing it between the client and server targets keeps both sides in
/// sync. `Data` values are encoded as Base64 strings by `JSONEncoder`.
public struct AssertionPayload: Sendable, Hashable, Codable {
    /// The identifier of the key that signed the assertion.
    public var keyID: AppAttestKeyID

    /// The CBOR-encoded assertion object produced by
    /// `DCAppAttestService.generateAssertion(_:clientDataHash:)`.
    public var assertion: Data

    /// The exact bytes the client hashed to produce the `clientDataHash` it
    /// passed to App Attest — typically the request body with the server
    /// challenge embedded.
    public var clientData: Data

    /// Creates an assertion payload.
    public init(keyID: AppAttestKeyID, assertion: Data, clientData: Data) {
        self.keyID = keyID
        self.assertion = assertion
        self.clientData = clientData
    }
}
