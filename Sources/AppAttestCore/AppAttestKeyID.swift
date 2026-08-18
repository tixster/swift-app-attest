import Foundation

/// The identifier of an App Attest key pair.
///
/// `DCAppAttestService.generateKey()` returns the key identifier as a Base64-encoded
/// string. The decoded value is the SHA-256 hash of the public key (in X9.62
/// uncompressed point format), which is why the raw form is always 32 bytes.
///
/// The identifier is safe to transmit to your server: the server needs it both to
/// verify the attestation object and to look up the stored public key when
/// verifying assertions.
public struct AppAttestKeyID: Sendable, Hashable {
    /// The Base64-encoded key identifier, exactly as returned by
    /// `DCAppAttestService.generateKey()`.
    public let base64EncodedString: String

    /// Creates a key identifier from the Base64-encoded string returned by
    /// `DCAppAttestService.generateKey()`.
    public init(base64EncodedString: String) {
        self.base64EncodedString = base64EncodedString
    }

    /// Creates a key identifier from its raw bytes (the SHA-256 hash of the
    /// attested public key).
    public init(rawBytes: Data) {
        self.base64EncodedString = rawBytes.base64EncodedString()
    }

    /// The decoded key identifier bytes, or `nil` if ``base64EncodedString``
    /// isn't valid Base64.
    ///
    /// A valid App Attest key identifier is always 32 bytes long.
    public var rawBytes: Data? {
        Data(base64Encoded: base64EncodedString)
    }
}

extension AppAttestKeyID: Codable {
    /// Encodes the identifier as a single Base64 string.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64EncodedString)
    }

    /// Decodes the identifier from a single Base64 string.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.init(base64EncodedString: try container.decode(String.self))
    }
}

extension AppAttestKeyID: CustomStringConvertible {
    public var description: String {
        base64EncodedString
    }
}
