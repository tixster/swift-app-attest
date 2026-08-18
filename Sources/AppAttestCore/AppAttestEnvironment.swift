import Foundation

/// The App Attest environment a key was generated in.
///
/// Apps generate keys in the ``development`` environment while running from Xcode,
/// and in the ``production`` environment when distributed through the App Store,
/// TestFlight, or with an enterprise certificate. Attestations, assertions, and
/// receipts from one environment are never valid in the other.
///
/// The environment is selected by the `com.apple.developer.devicecheck.appattest-environment`
/// entitlement on the client and is encoded into every attestation's AAGUID field.
public enum AppAttestEnvironment: String, Sendable, Codable, Hashable, CaseIterable {
    /// The sandbox environment used while developing and testing your app.
    case development

    /// The environment used by apps distributed through the App Store, TestFlight,
    /// or with an enterprise certificate.
    case production

    /// The 16-byte AAGUID value that identifies this environment inside an
    /// attestation's authenticator data.
    ///
    /// The development environment uses the ASCII bytes of `appattestdevelop`;
    /// the production environment uses `appattest` followed by seven `0x00` bytes.
    public var aaguid: Data {
        switch self {
        case .development:
            return Data("appattestdevelop".utf8)
        case .production:
            return Data("appattest".utf8) + Data(repeating: 0x00, count: 7)
        }
    }

    /// Creates an environment from a 16-byte AAGUID value found in authenticator data.
    ///
    /// - Parameter aaguid: The AAGUID bytes extracted from an attestation object.
    /// - Returns: `nil` if the value doesn't match either App Attest environment.
    public init?(aaguid: Data) {
        for environment in Self.allCases where environment.aaguid == aaguid {
            self = environment
            return
        }
        return nil
    }
}
