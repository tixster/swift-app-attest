import Crypto
import Foundation
import AppAttestCore

/// The decoded form of an App Attest assertion object.
///
/// Assertion objects are CBOR maps of the shape:
///
/// ```text
/// {
///   signature: <bytes>,
///   authenticatorData: <bytes>
/// }
/// ```
///
/// Most servers should call ``AssertionVerifier`` instead of using this type
/// directly; it's exposed for diagnostics and custom pipelines.
public struct AssertionObject: Sendable, Hashable {
    /// The DER-encoded ECDSA signature.
    public let signature: Data

    /// The parsed authenticator data.
    public let authenticatorData: AuthenticatorData

    /// Decodes an assertion object from its CBOR encoding.
    ///
    /// - Throws: ``AppAttestVerificationError/malformedAssertion(reason:)``.
    public init(parsing data: Data) throws(AppAttestVerificationError) {
        func fail(_ reason: String) -> AppAttestVerificationError {
            .malformedAssertion(reason: reason)
        }

        let root: CBOR
        do {
            root = try CBOR.decode(data)
        } catch {
            throw fail("invalid CBOR: \(error)")
        }

        guard let signature = root["signature"]?.bytesValue else {
            throw fail("missing signature entry")
        }
        self.signature = signature

        guard let authData = root["authenticatorData"]?.bytesValue else {
            throw fail("missing authenticatorData entry")
        }
        self.authenticatorData = try AuthenticatorData(parsing: authData, source: .assertion)
    }
}

/// The outcome of a successful assertion verification.
public struct VerifiedAssertion: Sendable {
    /// The counter from the assertion. Persist it — the next assertion for
    /// this key must carry a strictly greater value.
    public let signCount: UInt32

    /// The launch category of the app binary, when Apple included it.
    public let validationCategory: AppAttestValidationCategory?

    /// The version of the distributed app, when Apple included it.
    public let bundleVersion: String?

    /// The parsed authenticator data, for custom checks.
    public let authenticatorData: AuthenticatorData
}

/// Verifies App Attest assertion objects against a previously attested key.
///
/// Implements the steps of Apple's guide *Validating apps that connect to your
/// server*: the signature over `SHA256(authenticatorData || SHA256(clientData))`,
/// the App ID (RP ID) check, the monotonically increasing counter, and — when
/// you supply the expected challenge — the challenge embedded in the client data.
///
/// ```swift
/// let verifier = AssertionVerifier(configuration: configuration)
/// let result = try verifier.verify(
///     assertion: payload.assertion,
///     clientData: payload.clientData,
///     publicKey: storedKey.publicKey,
///     previousSignCount: storedKey.signCount,
///     expectedChallenge: storedChallenge,
///     challengeExtractor: { clientData in
///         try JSONDecoder().decode(MyRequest.self, from: clientData).challenge
///     }
/// )
/// storedKey.signCount = result.signCount  // persist
/// ```
public struct AssertionVerifier: Sendable {
    /// The verifier's configuration. Only the App ID fields are used here.
    public let configuration: AppAttestConfiguration

    /// Creates a verifier.
    public init(configuration: AppAttestConfiguration) {
        self.configuration = configuration
    }

    /// Verifies an assertion object.
    ///
    /// - Parameters:
    ///   - assertion: The CBOR-encoded assertion object from the client.
    ///   - clientData: The exact bytes the client hashed when generating the
    ///     assertion (typically the request body with the challenge embedded).
    ///   - publicKey: The public key stored after attestation for this key ID.
    ///   - previousSignCount: The counter stored from the attestation or the
    ///     last verified assertion. The assertion is rejected unless its
    ///     counter is strictly greater.
    ///   - expectedChallenge: The one-time challenge your server issued for
    ///     this request. When `nil`, the challenge check is skipped and you're
    ///     responsible for validating it yourself.
    ///   - challengeExtractor: How to pull the embedded challenge out of
    ///     `clientData` — for example, decoding your request format. The
    ///     library never parses `clientData` itself, so any format and field
    ///     name work. When `nil`, `clientData` is compared to
    ///     `expectedChallenge` directly, which suits clients that sign the
    ///     bare challenge. Errors it throws surface as
    ///     ``AppAttestVerificationError/challengeExtractionFailed(reason:)``.
    /// - Returns: The verified counter and extension values to persist.
    /// - Throws: ``AppAttestVerificationError`` naming the failed check.
    public func verify(
        assertion: Data,
        clientData: Data,
        publicKey: P256.Signing.PublicKey,
        previousSignCount: UInt32,
        expectedChallenge: Data? = nil,
        challengeExtractor: (@Sendable (Data) throws -> Data)? = nil
    ) throws(AppAttestVerificationError) -> VerifiedAssertion {
        let object = try AssertionObject(parsing: assertion)
        let authenticatorData = object.authenticatorData

        // Steps 1–3: verify the signature over the nonce.
        let clientDataHash = Data(SHA256.hash(data: clientData))
        let nonce = SHA256.hash(data: authenticatorData.rawBytes + clientDataHash)
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: object.signature) else {
            throw AppAttestVerificationError.invalidSignature
        }
        // Apple's guide only says the signature must be "valid for nonce",
        // leaving open whether the nonce is the signed digest or the signed
        // message — and devices disagree in practice. Both readings cover
        // exactly the same bytes and both demand the attested private key, so
        // accepting either is a compatibility measure, not a weaker check.
        let signsNonceAsDigest = publicKey.isValidSignature(signature, for: nonce)
        let signsNonceAsMessage = publicKey.isValidSignature(signature, for: Data(nonce))
        guard signsNonceAsDigest || signsNonceAsMessage else {
            throw AppAttestVerificationError.invalidSignature
        }

        // Step 4: the RP ID hash is the SHA-256 hash of the App ID.
        let appIDHash = Data(SHA256.hash(data: Data(configuration.appIdentifier.utf8)))
        guard authenticatorData.rpIdHash == appIDHash else {
            throw AppAttestVerificationError.appIDMismatch
        }

        // Step 5: the counter must increase with every assertion.
        guard authenticatorData.signCount > previousSignCount else {
            throw AppAttestVerificationError.counterNotIncreasing(
                previous: previousSignCount,
                received: authenticatorData.signCount
            )
        }

        // Step 6: the embedded challenge must match the one the server issued.
        if let expectedChallenge {
            let embedded: Data
            if let challengeExtractor {
                do {
                    embedded = try challengeExtractor(clientData)
                } catch {
                    throw AppAttestVerificationError.challengeExtractionFailed(
                        reason: String(describing: error)
                    )
                }
            } else {
                embedded = clientData
            }
            guard embedded == expectedChallenge else {
                throw AppAttestVerificationError.challengeMismatch
            }
        }

        return VerifiedAssertion(
            signCount: authenticatorData.signCount,
            validationCategory: authenticatorData.extensions?.validationCategory,
            bundleVersion: authenticatorData.extensions?.bundleVersion,
            authenticatorData: authenticatorData
        )
    }

    /// Verifies an assertion object using a stored X9.63 public key
    /// representation.
    ///
    /// A convenience over
    /// ``verify(assertion:clientData:publicKey:previousSignCount:expectedChallenge:challengeExtractor:)``
    /// for servers that persist `VerifiedAttestation/publicKeyX963Representation`.
    ///
    /// - Throws: ``AppAttestVerificationError/unsupportedPublicKey`` when the
    ///   bytes aren't a valid P-256 public key, or any other
    ///   ``AppAttestVerificationError`` from the underlying checks.
    public func verify(
        assertion: Data,
        clientData: Data,
        publicKeyX963Representation: Data,
        previousSignCount: UInt32,
        expectedChallenge: Data? = nil,
        challengeExtractor: (@Sendable (Data) throws -> Data)? = nil
    ) throws(AppAttestVerificationError) -> VerifiedAssertion {
        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyX963Representation) else {
            throw AppAttestVerificationError.unsupportedPublicKey
        }
        return try verify(
            assertion: assertion,
            clientData: clientData,
            publicKey: publicKey,
            previousSignCount: previousSignCount,
            expectedChallenge: expectedChallenge,
            challengeExtractor: challengeExtractor
        )
    }
}
