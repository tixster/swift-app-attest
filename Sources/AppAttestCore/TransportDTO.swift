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
