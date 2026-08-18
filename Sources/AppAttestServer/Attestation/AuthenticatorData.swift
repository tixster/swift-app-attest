import Foundation
import AppAttestCore

/// The category of executable that produced an attestation or assertion,
/// reported by the `apple_validation_category_01` authenticator-data extension.
///
/// Modeled as a raw-value wrapper (not an enum) so that categories Apple adds
/// in the future still parse.
public struct AppAttestValidationCategory: RawRepresentable, Sendable, Hashable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Invalid.
    public static let invalid = Self(rawValue: 0)
    /// An operating system executable.
    public static let operatingSystem = Self(rawValue: 1)
    /// An executable distributed through TestFlight.
    public static let testFlight = Self(rawValue: 2)
    /// An executable signed by a development code-signing identity.
    public static let development = Self(rawValue: 3)
    /// An executable distributed through the App Store.
    public static let appStore = Self(rawValue: 4)
    /// An executable distributed with an Enterprise profile or ad hoc.
    public static let enterprise = Self(rawValue: 5)
    /// An executable signed with Developer ID.
    public static let developerID = Self(rawValue: 6)
    /// An executable signed with a code-signing identity that matches no other category.
    public static let uncategorized = Self(rawValue: 10)
}

/// The optional extensions Apple embeds in authenticator data.
public struct AuthenticatorDataExtensions: Sendable, Hashable {
    /// The launch category of the app binary (`apple_validation_category_01`).
    public let validationCategory: AppAttestValidationCategory?

    /// The version of the distributed app (`apple_bundle_version_01`).
    public let bundleVersion: String?

    init(cbor: CBOR) {
        // Apple documents the long key names for attestations and shorthand
        // names for assertions; accept both.
        let categoryValue =
            cbor["apple_validation_category_01"]?.unsignedValue
            ?? cbor["validationCategory"]?.unsignedValue
        if let categoryValue, let raw = UInt32(exactly: categoryValue) {
            self.validationCategory = AppAttestValidationCategory(rawValue: raw)
        } else {
            self.validationCategory = nil
        }
        self.bundleVersion =
            cbor["apple_bundle_version_01"]?.textValue
            ?? cbor["bundleVersion"]?.textValue
    }
}

/// The parsed WebAuthn-style authenticator data embedded in App Attest
/// attestation and assertion objects.
public struct AuthenticatorData: Sendable, Hashable {
    /// The flags byte of the authenticator data.
    public struct Flags: OptionSet, Sendable, Hashable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Attested credential data follows the counter (`AT`, bit 6).
        public static let attestedCredentialData = Flags(rawValue: 0x40)
        /// An extensions map terminates the structure (`ED`, bit 7).
        public static let extensionData = Flags(rawValue: 0x80)
    }

    /// The exact bytes this structure was parsed from. Needed for the nonce
    /// computations during attestation and assertion verification.
    public let rawBytes: Data

    /// `SHA256(appID)` — the hash of your app's App ID.
    public let rpIdHash: Data

    /// The parsed flags byte.
    public let flags: Flags

    /// The number of assertions the attested key has signed so far.
    public let signCount: UInt32

    /// The 16-byte environment marker; present when
    /// ``Flags-swift.struct/attestedCredentialData`` is set.
    public let aaguid: Data?

    /// The credential identifier — for App Attest, the SHA-256 hash of the
    /// attested public key. Present in attestations only.
    public let credentialID: Data?

    /// The raw CBOR bytes of the COSE-encoded credential public key, when present.
    public let credentialPublicKey: Data?

    /// Apple's authenticator-data extensions, when present.
    public let extensions: AuthenticatorDataExtensions?

    /// Parses authenticator data from an attestation or assertion object.
    ///
    /// - Throws: ``AppAttestVerificationError/malformedAuthenticatorData(reason:)``.
    public init(parsing data: Data) throws(AppAttestVerificationError) {
        func fail(_ reason: String) -> AppAttestVerificationError {
            .malformedAuthenticatorData(reason: reason)
        }

        let bytes = [UInt8](data)
        guard bytes.count >= 37 else {
            throw fail("expected at least 37 bytes, got \(bytes.count)")
        }

        self.rawBytes = data
        self.rpIdHash = Data(bytes[0..<32])
        let flags = Flags(rawValue: bytes[32])
        self.flags = flags
        self.signCount = bytes[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }

        var rest = Data(bytes[37...])

        if flags.contains(.attestedCredentialData) {
            guard rest.count >= 18 else {
                throw fail("attested credential data is truncated")
            }
            self.aaguid = rest.prefix(16)
            let lengthBytes = [UInt8](rest.dropFirst(16).prefix(2))
            let credentialIDLength = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])
            rest = rest.dropFirst(18)
            guard rest.count >= credentialIDLength else {
                throw fail("credentialId is truncated")
            }
            self.credentialID = rest.prefix(credentialIDLength)
            rest = rest.dropFirst(credentialIDLength)
        } else {
            self.aaguid = nil
            self.credentialID = nil
        }

        // What follows is a run of CBOR items: the COSE credential key (when
        // attested credential data is present and the authenticator emitted
        // one) and/or the extensions map (when the ED flag is set).
        var reader = CBOR.Reader(Data(rest))
        var trailingItems: [(item: CBOR, rawBytes: Data)] = []
        while !reader.isAtEnd {
            guard trailingItems.count < 2 else {
                throw fail("unexpected trailing bytes after extensions")
            }
            do {
                trailingItems.append(try reader.decodeItemCapturingBytes())
            } catch {
                throw fail("undecodable trailing CBOR: \(error)")
            }
        }

        let expectsExtensions = flags.contains(.extensionData)
        switch (flags.contains(.attestedCredentialData), trailingItems.count) {
        case (_, 0):
            guard !expectsExtensions else {
                throw fail("ED flag is set but no extensions map is present")
            }
            self.credentialPublicKey = nil
            self.extensions = nil
        case (true, 2):
            guard expectsExtensions else {
                throw fail("unexpected trailing bytes after credential public key")
            }
            self.credentialPublicKey = trailingItems[0].rawBytes
            self.extensions = AuthenticatorDataExtensions(cbor: trailingItems[1].item)
        case (true, 1):
            // A single item is the extensions map when ED is set, otherwise
            // it's the COSE credential key.
            if expectsExtensions {
                self.credentialPublicKey = nil
                self.extensions = AuthenticatorDataExtensions(cbor: trailingItems[0].item)
            } else {
                self.credentialPublicKey = trailingItems[0].rawBytes
                self.extensions = nil
            }
        case (false, 1):
            guard expectsExtensions else {
                throw fail("unexpected trailing bytes")
            }
            self.credentialPublicKey = nil
            self.extensions = AuthenticatorDataExtensions(cbor: trailingItems[0].item)
        default:
            throw fail("unexpected trailing bytes")
        }
    }
}
