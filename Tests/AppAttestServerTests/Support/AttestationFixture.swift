import Crypto
import Foundation
import X509
@testable import AppAttestServer

/// Builds synthetic App Attest attestation objects, with knobs for producing
/// each kind of invalid input.
struct AttestationFixture {
    struct Options {
        var teamIdentifier = "TEAM123456"
        var bundleIdentifier = "com.example.app"
        var environment: AppAttestEnvironment = .development
        var challenge = Data("one-time-challenge".utf8)
        var counter: UInt32 = 0
        var format = "apple-appattest"
        var receipt = Data("receipt-bytes".utf8)
        var includeAuthenticatorExtensions = true
        var validationCategory: UInt64 = 4
        var bundleVersion = "1.2.3"
        /// Overrides the AAGUID bytes in the authenticator data.
        var aaguidOverride: Data?
        /// Overrides the credential ID in the authenticator data.
        var credentialIDOverride: Data?
        /// Overrides the nonce embedded in the credential certificate.
        var certificateNonceOverride: Data?
        /// Adds the macOS access-control policy extension with these octets.
        var aclBlob: Data?
        /// Overrides the RP ID hash (defaults to SHA256 of the App ID).
        var rpIdHashOverride: Data?

        var appIdentifier: String { "\(teamIdentifier).\(bundleIdentifier)" }
    }

    let attestation: Data
    let keyID: AppAttestKeyID
    let challenge: Data
    let attestedKey: P256.Signing.PrivateKey
    let chain: TestCertificateFactory.Chain
    let authenticatorData: Data
    let options: Options

    /// A configuration whose trust roots accept this fixture's chain.
    var configuration: AppAttestConfiguration {
        AppAttestConfiguration(
            teamIdentifier: options.teamIdentifier,
            bundleIdentifier: options.bundleIdentifier,
            environments: [.development, .production],
            attestationTrustRoots: [chain.root]
        )
    }

    static func make(_ configure: (inout Options) -> Void = { _ in }) throws -> AttestationFixture {
        var options = Options()
        configure(&options)

        let attestedKey = P256.Signing.PrivateKey()
        let publicKeyX963 = attestedKey.publicKey.x963Representation
        let keyIDBytes = Data(SHA256.hash(data: publicKeyX963))

        let authenticatorData = makeAuthenticatorData(
            options: options,
            publicKeyX963: publicKeyX963,
            keyIDBytes: keyIDBytes
        )

        let clientDataHash = Data(SHA256.hash(data: options.challenge))
        let nonce =
            options.certificateNonceOverride
            ?? Data(SHA256.hash(data: authenticatorData + clientDataHash))

        let chain = try TestCertificateFactory.makeChain(
            leafPublicKey: attestedKey.publicKey,
            nonce: nonce,
            aclBlob: options.aclBlob
        )

        let attestation = TestCBOR.map([
            (.text("fmt"), .text(options.format)),
            (
                .text("attStmt"),
                .map([
                    (.text("x5c"), .array([
                        .bytes(try chain.leaf.derBytes),
                        .bytes(try chain.intermediate.derBytes),
                    ])),
                    (.text("receipt"), .bytes(options.receipt)),
                ])
            ),
            (.text("authData"), .bytes(authenticatorData)),
        ]).encoded

        return AttestationFixture(
            attestation: attestation,
            keyID: AppAttestKeyID(rawBytes: keyIDBytes),
            challenge: options.challenge,
            attestedKey: attestedKey,
            chain: chain,
            authenticatorData: authenticatorData,
            options: options
        )
    }

    /// Assembles WebAuthn-style authenticator data with attested credential data.
    static func makeAuthenticatorData(
        options: Options,
        publicKeyX963: Data,
        keyIDBytes: Data
    ) -> Data {
        let rpIdHash =
            options.rpIdHashOverride
            ?? Data(SHA256.hash(data: Data(options.appIdentifier.utf8)))
        let aaguid = options.aaguidOverride ?? options.environment.aaguid
        let credentialID = options.credentialIDOverride ?? keyIDBytes

        var flags: UInt8 = 0x40  // AT
        if options.includeAuthenticatorExtensions {
            flags |= 0x80  // ED
        }

        var data = Data()
        data += rpIdHash
        data.append(flags)
        data += options.counter.bigEndianBytes
        data += aaguid
        data.append(UInt8(credentialID.count >> 8))
        data.append(UInt8(credentialID.count & 0xff))
        data += credentialID
        data += coseKey(x963: publicKeyX963)
        if options.includeAuthenticatorExtensions {
            data += TestCBOR.map([
                (.text("apple_validation_category_01"), .unsigned(options.validationCategory)),
                (.text("apple_bundle_version_01"), .text(options.bundleVersion)),
            ]).encoded
        }
        return data
    }

    /// Encodes a P-256 public key as a COSE_Key CBOR map (77 bytes).
    static func coseKey(x963: Data) -> Data {
        let x = x963.dropFirst(1).prefix(32)
        let y = x963.suffix(32)
        return TestCBOR.map([
            (.int(1), .int(2)),  // kty: EC2
            (.int(3), .int(-7)),  // alg: ES256
            (.int(-1), .int(1)),  // crv: P-256
            (.int(-2), .bytes(Data(x))),
            (.int(-3), .bytes(Data(y))),
        ]).encoded
    }
}

/// Builds synthetic assertion objects for a given attested key.
enum AssertionFixture {
    struct Options {
        var appIdentifier = "TEAM123456.com.example.app"
        var counter: UInt32 = 1
        var includeExtensions = false
        var validationCategory: UInt64 = 4
        var bundleVersion = "1.2.3"
        var rpIdHashOverride: Data?
        /// When set, the signature is produced over these bytes instead of the
        /// real nonce, yielding an invalid signature.
        var corruptSignature = false
        /// iOS 26 sets the `AT` flag in assertion authenticator data without
        /// appending an attested credential data section.
        var spuriousAttestedCredentialDataFlag = false
        /// Sign the nonce as a *message* (ECDSA-SHA256 hashes it again)
        /// instead of signing the nonce digest directly.
        var signsNonceAsMessage = false
    }

    static func make(
        key: P256.Signing.PrivateKey,
        clientData: Data,
        _ configure: (inout Options) -> Void = { _ in }
    ) throws -> Data {
        var options = Options()
        configure(&options)

        let rpIdHash =
            options.rpIdHashOverride
            ?? Data(SHA256.hash(data: Data(options.appIdentifier.utf8)))

        var authenticatorData = Data()
        authenticatorData += rpIdHash
        var flags: UInt8 = options.includeExtensions ? 0x80 : 0x00
        if options.spuriousAttestedCredentialDataFlag {
            flags |= 0x40
        }
        authenticatorData.append(flags)
        authenticatorData += options.counter.bigEndianBytes
        if options.includeExtensions {
            authenticatorData += TestCBOR.map([
                (.text("apple_validation_category_01"), .unsigned(options.validationCategory)),
                (.text("apple_bundle_version_01"), .text(options.bundleVersion)),
            ]).encoded
        }

        let clientDataHash = Data(SHA256.hash(data: clientData))
        var message = authenticatorData + clientDataHash
        if options.corruptSignature {
            message += Data("tampered".utf8)
        }
        let nonce = SHA256.hash(data: message)
        let signature =
            options.signsNonceAsMessage
            ? try key.signature(for: Data(nonce))
            : try key.signature(for: nonce)

        return TestCBOR.map([
            (.text("signature"), .bytes(signature.derRepresentation)),
            (.text("authenticatorData"), .bytes(authenticatorData)),
        ]).encoded
    }
}
