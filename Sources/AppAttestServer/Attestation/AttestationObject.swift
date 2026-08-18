import Foundation

/// The decoded form of an App Attest attestation object.
///
/// Attestation objects are CBOR maps in the WebAuthn attestation-object shape,
/// using Apple's custom `apple-appattest` statement format:
///
/// ```text
/// {
///   fmt: "apple-appattest",
///   attStmt: {
///     x5c: [ credCert, intermediateCA ],
///     receipt: <bytes>
///   },
///   authData: <bytes>
/// }
/// ```
///
/// Most servers should call ``AttestationVerifier`` instead of using this type
/// directly; it's exposed for diagnostics and custom pipelines.
public struct AttestationObject: Sendable, Hashable {
    /// The statement format identifier Apple uses for App Attest.
    public static let appleAppAttestFormat = "apple-appattest"

    /// The attestation statement format (`fmt`).
    public let format: String

    /// The DER-encoded certificates from the `x5c` array, starting with the
    /// credential certificate.
    public let certificateChain: [Data]

    /// The receipt from the attestation statement. Use it with
    /// ``FraudAssessmentClient`` to request Apple's risk metric.
    public let receipt: Data

    /// The parsed authenticator data.
    public let authenticatorData: AuthenticatorData

    /// Decodes an attestation object from its CBOR encoding.
    ///
    /// - Throws: ``AppAttestVerificationError/malformedAttestation(reason:)``.
    public init(parsing data: Data) throws(AppAttestVerificationError) {
        func fail(_ reason: String) -> AppAttestVerificationError {
            .malformedAttestation(reason: reason)
        }

        let root: CBOR
        do {
            root = try CBOR.decode(data)
        } catch {
            throw fail("invalid CBOR: \(error)")
        }

        guard let format = root["fmt"]?.textValue else {
            throw fail("missing fmt entry")
        }
        self.format = format

        guard let statement = root["attStmt"], statement.mapValue != nil else {
            throw fail("missing attStmt entry")
        }
        guard let x5c = statement["x5c"]?.arrayValue else {
            throw fail("missing attStmt.x5c entry")
        }
        var certificateChain: [Data] = []
        for entry in x5c {
            guard let certificate = entry.bytesValue else {
                throw fail("attStmt.x5c contains a non-byte-string entry")
            }
            certificateChain.append(certificate)
        }
        self.certificateChain = certificateChain

        guard let receipt = statement["receipt"]?.bytesValue else {
            throw fail("missing attStmt.receipt entry")
        }
        self.receipt = receipt

        guard let authData = root["authData"]?.bytesValue else {
            throw fail("missing authData entry")
        }
        self.authenticatorData = try AuthenticatorData(parsing: authData)
    }
}
