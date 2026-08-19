import Crypto
import Foundation

/// The credentials used to authenticate against Apple's fraud-assessment
/// endpoint.
///
/// Create the key in the Apple Developer portal — Certificates, Identifiers &
/// Profiles → Keys → Create a key — with the **DeviceCheck** service enabled,
/// and download its `.p8` file. (This is the same kind of key used for the
/// DeviceCheck server API and APNs provider tokens, not an App Store Connect
/// API key.)
public struct DeviceCheckCredentials: Sendable {
    /// The 10-character identifier of the key (`kid` JWT header).
    public let keyIdentifier: String

    /// Your 10-character Team ID (`iss` JWT claim).
    public let teamIdentifier: String

    /// The P-256 private key from the `.p8` file.
    public let privateKey: P256.Signing.PrivateKey

    /// Creates credentials from an already-parsed private key.
    public init(keyIdentifier: String, teamIdentifier: String, privateKey: P256.Signing.PrivateKey) {
        self.keyIdentifier = keyIdentifier
        self.teamIdentifier = teamIdentifier
        self.privateKey = privateKey
    }

    /// Creates credentials from the PEM contents of a `.p8` file.
    ///
    /// - Throws: A `CryptoKit` error when the PEM isn't a valid P-256 private key.
    public init(keyIdentifier: String, teamIdentifier: String, privateKeyPEM: String) throws {
        self.init(
            keyIdentifier: keyIdentifier,
            teamIdentifier: teamIdentifier,
            privateKey: try P256.Signing.PrivateKey(pemRepresentation: privateKeyPEM)
        )
    }
}
