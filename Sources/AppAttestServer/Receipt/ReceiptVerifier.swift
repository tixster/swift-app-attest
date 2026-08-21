import Crypto
import Foundation
@_spi(CMS) import X509

/// Verifies App Attest receipts.
///
/// Follows the checks from Apple's guide *Assessing fraud risk*: the PKCS #7
/// signature against Apple Root CA - G3, the App ID in field 2, the attested
/// public key in field 3, the creation time in field 12, and the expiration
/// time in field 21.
///
/// ```swift
/// let verifier = ReceiptVerifier(configuration: configuration)
///
/// // Verifying the receipt that came with an attestation — Apple recommends
/// // rejecting receipts older than five minutes here:
/// let receipt = try await verifier.verify(
///     receipt: attestationResult.receipt,
///     expectedPublicKey: attestationResult.publicKey,
///     maximumCreationAge: 300
/// )
///
/// // Verifying a refreshed receipt from the fraud-assessment endpoint:
/// let refreshed = try await verifier.verify(
///     receipt: newReceiptData,
///     expectedPublicKey: attestationResult.publicKey
/// )
/// if let riskMetric = refreshed.riskMetric { /* assess */ }
/// ```
public struct ReceiptVerifier: Sendable {
    /// The verifier's configuration.
    public let configuration: AppAttestConfiguration

    /// Creates a verifier.
    public init(configuration: AppAttestConfiguration) {
        self.configuration = configuration
    }

    /// Verifies a receipt and returns its decoded payload.
    ///
    /// - Parameters:
    ///   - receipt: The PKCS #7 receipt — from an attestation object or from
    ///     ``FraudAssessmentClient/refreshReceipt(_:)``.
    ///   - expectedPublicKey: The attested public key stored for this device.
    ///     When supplied, field 3 must contain a certificate for exactly this
    ///     key.
    ///   - maximumCreationAge: When supplied, the receipt's creation time
    ///     (field 12) must be no older than this many seconds. Apple
    ///     recommends five minutes (300) for receipts that accompany an
    ///     attestation, to thwart replays.
    ///   - date: The reference time for freshness and expiration checks.
    ///     Defaults to now; override it only in tests.
    /// - Returns: The decoded receipt.
    /// - Throws: ``AppAttestReceiptError`` naming the failed check.
    public func verify(
        receipt: Data,
        expectedPublicKey: P256.Signing.PublicKey? = nil,
        maximumCreationAge: TimeInterval? = nil,
        at date: Date = Date()
    ) async throws(AppAttestReceiptError) -> AppAttestReceipt {
        // Apple encodes receipts in BER (indefinite lengths, chunked octet
        // strings), а swift-certificates parses strict DER — normalize first.
        // The signed regions are DER already and survive byte-for-byte, so
        // signatures keep verifying; see ``BERNormalizer``.
        let derReceipt: Data
        do {
            derReceipt = try BERNormalizer.normalizeToDER(receipt)
        } catch {
            throw AppAttestReceiptError.malformedReceipt(reason: "not valid BER: \(error)")
        }

        // Verify the PKCS #7 signature and the signing chain up to the Apple root.
        let roots = configuration.receiptTrustRoots ?? [AppleTrustRoots.appleRootCAG3]
        let signatureResult = await CMS.isValidAttachedSignature(
            signatureBytes: [UInt8](derReceipt),
            trustRoots: CertificateStore(roots)
        ) {
            RFC5280Policy()
        }
        if case .failure(let error) = signatureResult {
            throw AppAttestReceiptError.invalidSignature(reason: String(describing: error))
        }

        // Parse the payload.
        let payload = try PKCS7Container.encapsulatedContent(of: receipt)
        let parsed = try AppAttestReceipt(payload: payload)

        // Field 2: the receipt must be for this app.
        guard parsed.appID == configuration.appIdentifier else {
            throw AppAttestReceiptError.appIDMismatch(
                expected: configuration.appIdentifier,
                received: parsed.appID
            )
        }

        // Field 12: optionally require freshness.
        if let maximumCreationAge {
            guard date.timeIntervalSince(parsed.creationTime) <= maximumCreationAge else {
                throw AppAttestReceiptError.receiptTooOld(creationTime: parsed.creationTime)
            }
        }

        // Field 21: the receipt must not be expired.
        guard parsed.expirationTime > date else {
            throw AppAttestReceiptError.receiptExpired(expirationTime: parsed.expirationTime)
        }

        // Field 3: the attested key must match the one stored at enrollment.
        if let expectedPublicKey {
            let certificate = try parsed.attestedCertificate()
            guard
                let receiptKey = P256.Signing.PublicKey(certificate.publicKey),
                receiptKey.x963Representation == expectedPublicKey.x963Representation
            else {
                throw AppAttestReceiptError.publicKeyMismatch
            }
        }

        return parsed
    }
}
