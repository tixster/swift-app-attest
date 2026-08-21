import Crypto
import Foundation
import AppAttestCore
import X509

/// The outcome of a successful attestation verification.
///
/// Persist ``publicKey`` (or one of its serialized forms), ``receipt``,
/// ``environment``, and ``signCount``, keyed by user and device. You need the
/// public key and the counter to verify assertions, and the receipt to request
/// fraud-risk metrics. As an extra replay protection, reject enrollment if the
/// public key is already associated with another user.
public struct VerifiedAttestation: Sendable {
    /// The identifier of the attested key, as supplied by the client.
    public let keyID: AppAttestKeyID

    /// The attested P-256 public key extracted from the credential certificate.
    public let publicKey: P256.Signing.PublicKey

    /// The receipt to use with ``FraudAssessmentClient``.
    public let receipt: Data

    /// The environment the key was generated in.
    public let environment: AppAttestEnvironment

    /// The counter at attestation time; always `0`. Store it as the starting
    /// point for assertion counter checks.
    public let signCount: UInt32

    /// The launch category of the app binary, when Apple included it.
    public let validationCategory: AppAttestValidationCategory?

    /// The version of the distributed app, when Apple included it.
    public let bundleVersion: String?

    /// The credential certificate the public key was extracted from.
    public let credentialCertificate: Certificate

    /// The public key in X9.63 uncompressed point format (65 bytes).
    public var publicKeyX963Representation: Data {
        publicKey.x963Representation
    }

    /// The public key as a DER-encoded `SubjectPublicKeyInfo`.
    public var publicKeyDERRepresentation: Data {
        publicKey.derRepresentation
    }
}

/// Verifies App Attest attestation objects.
///
/// Implements every step of Apple's guide *Validating apps that connect to
/// your server*: certificate-chain validation against the App Attest root CA,
/// the nonce check, the key-identifier check, the App ID (RP ID) check, the
/// counter, the environment AAGUID, the credential ID, and — for macOS keys —
/// the access-control policy blob.
///
/// ```swift
/// let verifier = AttestationVerifier(
///     configuration: AppAttestConfiguration(
///         teamIdentifier: "A1B2C3D4E5",
///         bundleIdentifier: "com.example.app"
///     )
/// )
/// let result = try await verifier.verify(
///     attestation: payload.attestation,
///     keyID: payload.keyID,
///     challenge: storedChallenge
/// )
/// // persist result.publicKey, result.receipt, result.signCount
/// ```
///
/// > Important: The challenge must be a single-use random value your server
/// > generated for this enrollment. Invalidate it as soon as verification
/// > completes, whether or not it succeeds.
public struct AttestationVerifier: Sendable {
    /// The verifier's configuration.
    public let configuration: AppAttestConfiguration

    /// Creates a verifier.
    public init(configuration: AppAttestConfiguration) {
        self.configuration = configuration
    }

    /// Verifies an attestation object.
    ///
    /// - Parameters:
    ///   - attestation: The CBOR-encoded attestation object from the client.
    ///   - keyID: The key identifier the client sent alongside it.
    ///   - challenge: The one-time challenge your server issued for this
    ///     enrollment (the raw challenge, not its hash).
    /// - Returns: The verified key material and receipt to persist.
    /// - Throws: ``AppAttestVerificationError`` naming the failed check.
    ///
    /// Certificate validity is evaluated against the current time; verify
    /// attestations when you receive them.
    public func verify(
        attestation: Data,
        keyID: AppAttestKeyID,
        challenge: Data
    ) async throws(AppAttestVerificationError) -> VerifiedAttestation {
        guard let keyIDBytes = keyID.rawBytes else {
            throw AppAttestVerificationError.invalidKeyIdentifier
        }

        let object = try AttestationObject(parsing: attestation)
        guard object.format == AttestationObject.appleAppAttestFormat else {
            throw AppAttestVerificationError.unsupportedAttestationFormat(object.format)
        }

        // Step 1: verify the x5c chain up to the App Attest root CA, starting
        // from the credential certificate.
        guard let credentialCertificateData = object.certificateChain.first else {
            throw AppAttestVerificationError.certificateChainMissing
        }
        let credentialCertificate: Certificate
        let intermediates: [Certificate]
        do {
            credentialCertificate = try Certificate(derEncoded: [UInt8](credentialCertificateData))
            intermediates = try object.certificateChain.dropFirst().map {
                try Certificate(derEncoded: [UInt8]($0))
            }
        } catch {
            throw AppAttestVerificationError.malformedAttestation(reason: "undecodable certificate: \(error)")
        }

        let roots = configuration.attestationTrustRoots ?? [AppleTrustRoots.appAttestRootCA]
        var chainVerifier = Verifier(rootCertificates: CertificateStore(roots)) {
            RFC5280Policy()
        }
        let validation = await chainVerifier.validate(
            leaf: credentialCertificate,
            intermediates: CertificateStore(intermediates)
        )
        if case .couldNotValidate(let failures) = validation {
            throw AppAttestVerificationError.certificateChainValidationFailed(
                reason: failures.map { String(describing: $0) }.joined(separator: "; ")
            )
        }

        // Steps 2–3: recompute the nonce and compare it to the value embedded
        // in the credential certificate.
        let authenticatorData = object.authenticatorData
        let clientDataHash = Data(SHA256.hash(data: challenge))
        let nonce = Data(SHA256.hash(data: authenticatorData.rawBytes + clientDataHash))

        let certificateNonce: Data?
        do {
            certificateNonce = try AppleCertificateExtensions.nonce(in: credentialCertificate)
        } catch {
            throw AppAttestVerificationError.malformedAttestation(reason: "undecodable nonce extension: \(error)")
        }
        guard let certificateNonce else {
            throw AppAttestVerificationError.nonceExtensionMissing
        }
        guard certificateNonce == nonce else {
            throw AppAttestVerificationError.nonceMismatch
        }

        // Opt-in, macOS-only deployments: compare the key's access-control
        // policy blob to the macOS SIP + Full Security value. iOS 26
        // attestations carry the extension too, with different contents, so
        // this must stay off for iOS clients.
        if configuration.validatesMacOSAccessControlPolicy {
            let policy: Data?
            do {
                policy = try AppleCertificateExtensions.accessControlPolicy(in: credentialCertificate)
            } catch {
                throw AppAttestVerificationError.malformedAttestation(reason: "undecodable aclBlob extension: \(error)")
            }
            if let policy, policy != AppleCertificateExtensions.expectedAccessControlPolicy {
                throw AppAttestVerificationError.accessControlPolicyMismatch
            }
        }

        // Step 4: the key identifier is the SHA-256 hash of the credential
        // certificate's public key in X9.62 uncompressed point format.
        guard let publicKey = P256.Signing.PublicKey(credentialCertificate.publicKey) else {
            throw AppAttestVerificationError.unsupportedPublicKey
        }
        guard Data(SHA256.hash(data: publicKey.x963Representation)) == keyIDBytes else {
            throw AppAttestVerificationError.keyIdentifierMismatch
        }

        // Step 5: the RP ID hash is the SHA-256 hash of the App ID.
        let appIDHash = Data(SHA256.hash(data: Data(configuration.appIdentifier.utf8)))
        guard authenticatorData.rpIdHash == appIDHash else {
            throw AppAttestVerificationError.appIDMismatch
        }

        // Step 6: a fresh key has never signed an assertion.
        guard authenticatorData.signCount == 0 else {
            throw AppAttestVerificationError.invalidCounter(authenticatorData.signCount)
        }

        // Step 7: the AAGUID names the App Attest environment.
        guard let aaguid = authenticatorData.aaguid,
            let environment = AppAttestEnvironment(aaguid: aaguid)
        else {
            throw AppAttestVerificationError.unknownAAGUID(authenticatorData.aaguid ?? Data())
        }
        guard configuration.environments.contains(environment) else {
            throw AppAttestVerificationError.environmentNotAllowed(environment)
        }

        // Step 8: the credential ID equals the key identifier.
        guard authenticatorData.credentialID == keyIDBytes else {
            throw AppAttestVerificationError.credentialIDMismatch
        }

        return VerifiedAttestation(
            keyID: keyID,
            publicKey: publicKey,
            receipt: object.receipt,
            environment: environment,
            signCount: authenticatorData.signCount,
            validationCategory: authenticatorData.extensions?.validationCategory,
            bundleVersion: authenticatorData.extensions?.bundleVersion,
            credentialCertificate: credentialCertificate
        )
    }
}
