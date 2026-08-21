import Foundation
import AppAttestCore
import X509

/// Shared configuration for the server-side verifiers.
public struct AppAttestConfiguration: Sendable {
    /// Your 10-character Apple Developer Team ID (the App ID prefix).
    public var teamIdentifier: String

    /// Your app's bundle identifier.
    ///
    /// For macOS apps, use the App ID as it appears in the Identifier entry of
    /// your developer account (Apple substitutes it for the bundle ID in the
    /// RP ID hash).
    public var bundleIdentifier: String

    /// The App Attest environments to accept attestations from.
    ///
    /// Defaults to production only. Add `AppAttestEnvironment.development`
    /// for builds run from Xcode, but keep development keys out of production
    /// databases — receipts and metrics from one environment aren't valid in
    /// the other.
    public var environments: Set<AppAttestEnvironment>

    /// Trust roots for attestation certificate chains.
    ///
    /// Defaults to ``AppleTrustRoots/appAttestRootCA``. Override only in tests
    /// or if Apple ever rotates the root.
    public var attestationTrustRoots: [Certificate]?

    /// Trust roots for receipt (PKCS #7) signatures.
    ///
    /// Defaults to ``AppleTrustRoots/appleRootCAG3``. Override only in tests
    /// or if Apple ever rotates the root.
    public var receiptTrustRoots: [Certificate]?

    /// Whether to verify the key access-control policy extension (`aclBlob`)
    /// against the value Apple documents for macOS with SIP plus Full
    /// Security mode.
    ///
    /// Enable this **only when every client is a macOS app**. The extension
    /// is not macOS-exclusive: attestations from iOS 26 devices carry it too,
    /// with platform-specific contents, and nothing in the attestation tells
    /// the platforms apart — so with this check on, every legitimate iOS key
    /// is rejected with
    /// ``AppAttestVerificationError/accessControlPolicyMismatch``.
    /// Apple's step-by-step attestation validation guide doesn't include this
    /// comparison; it comes from the separate macOS guidance.
    public var validatesMacOSAccessControlPolicy: Bool

    /// The App ID: your Team ID, a period, and the bundle identifier.
    ///
    /// Its SHA-256 hash is the RP ID hash embedded in every attestation and
    /// assertion.
    public var appIdentifier: String {
        "\(teamIdentifier).\(bundleIdentifier)"
    }

    /// Creates a configuration.
    ///
    /// - Parameters:
    ///   - teamIdentifier: Your 10-character Team ID.
    ///   - bundleIdentifier: Your app's bundle identifier.
    ///   - environments: The environments to accept. Defaults to `[.production]`.
    ///   - attestationTrustRoots: Overrides the App Attest root CA (tests only).
    ///   - receiptTrustRoots: Overrides the receipt root CA (tests only).
    ///   - validatesMacOSAccessControlPolicy: See
    ///     ``validatesMacOSAccessControlPolicy``. Defaults to `false`; enable
    ///     only for macOS-only clients.
    public init(
        teamIdentifier: String,
        bundleIdentifier: String,
        environments: Set<AppAttestEnvironment> = [.production],
        attestationTrustRoots: [Certificate]? = nil,
        receiptTrustRoots: [Certificate]? = nil,
        validatesMacOSAccessControlPolicy: Bool = false
    ) {
        self.teamIdentifier = teamIdentifier
        self.bundleIdentifier = bundleIdentifier
        self.environments = environments
        self.attestationTrustRoots = attestationTrustRoots
        self.receiptTrustRoots = receiptTrustRoots
        self.validatesMacOSAccessControlPolicy = validatesMacOSAccessControlPolicy
    }
}
