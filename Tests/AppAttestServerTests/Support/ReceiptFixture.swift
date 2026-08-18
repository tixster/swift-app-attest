import Crypto
import Foundation
import SwiftASN1
@_spi(CMS) import X509
@testable import AppAttestServer

/// Builds synthetic App Attest receipts: an ASN.1 attribute payload wrapped in
/// an attached CMS signature from a throwaway "Apple" chain.
struct ReceiptFixture {
    struct Options {
        var appID = "TEAM123456.com.example.app"
        var receiptType = "RECEIPT"
        var creationTime = Date()
        var riskMetric: Int? = 3
        /// Encode the risk metric as a digit string instead of an INTEGER.
        var riskMetricAsString = false
        var notBefore: Date? = Date().addingTimeInterval(24 * 3600)
        var expirationTime = Date().addingTimeInterval(60 * 24 * 3600)
        var token = "dGVzdC10b2tlbg=="
        var clientHash = Data(repeating: 0x5a, count: 32)
        /// Omit numbered fields from the payload (to test missing-field errors).
        var omitFields: Set<Int> = []
    }

    let receipt: Data
    let signingChain: TestCertificateFactory.Chain
    /// The certificate embedded in field 3 (carries the attested public key).
    let attestedCertificate: Certificate
    let attestedKey: P256.Signing.PrivateKey
    let options: Options

    static func make(_ configure: (inout Options) -> Void = { _ in }) throws -> ReceiptFixture {
        var options = Options()
        configure(&options)

        // The "attested key" whose certificate goes into field 3.
        let attestedKey = P256.Signing.PrivateKey()
        let attestationChain = try TestCertificateFactory.makeChain(
            leafPublicKey: attestedKey.publicKey,
            nonce: Data(repeating: 0x01, count: 32)
        )
        let attestedCertificate = attestationChain.leaf

        let payload = try makePayload(
            options: options,
            attestedCertificateDER: try attestedCertificate.derBytes
        )

        // A separate chain that plays the role of Apple's receipt-signing PKI.
        let signingKey = P256.Signing.PrivateKey()
        let signingChain = try TestCertificateFactory.makeChain(
            leafPublicKey: signingKey.publicKey,
            nonce: nil
        )
        let signature = try CMS.sign(
            [UInt8](payload),
            signatureAlgorithm: .ecdsaWithSHA256,
            additionalIntermediateCertificates: [signingChain.intermediate],
            certificate: signingChain.leaf,
            privateKey: Certificate.PrivateKey(signingKey),
            detached: false
        )

        return ReceiptFixture(
            receipt: Data(signature),
            signingChain: signingChain,
            attestedCertificate: attestedCertificate,
            attestedKey: attestedKey,
            options: options
        )
    }

    /// A configuration whose receipt trust roots accept this fixture.
    var configuration: AppAttestConfiguration {
        AppAttestConfiguration(
            teamIdentifier: "TEAM123456",
            bundleIdentifier: "com.example.app",
            receiptTrustRoots: [signingChain.root]
        )
    }

    // MARK: Payload encoding

    static func makePayload(options: Options, attestedCertificateDER: Data) throws -> Data {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .set) { set in
            func appendField(_ type: Int, _ writeValue: (inout DER.Serializer) throws -> Void) throws {
                guard !options.omitFields.contains(type) else { return }
                var valueSerializer = DER.Serializer()
                try writeValue(&valueSerializer)
                try set.appendConstructedNode(identifier: .sequence) { field in
                    try field.serialize(type)
                    try field.serialize(1)  // version
                    try field.serialize(ASN1OctetString(contentBytes: valueSerializer.serializedBytes[...]))
                }
            }
            func utf8String(_ value: String) -> (inout DER.Serializer) throws -> Void {
                { serializer in
                    serializer.appendPrimitiveNode(identifier: .utf8String) { bytes in
                        bytes.append(contentsOf: Data(value.utf8))
                    }
                }
            }
            func ia5Date(_ value: Date) -> (inout DER.Serializer) throws -> Void {
                { serializer in
                    serializer.appendPrimitiveNode(
                        identifier: ASN1Identifier(tagWithNumber: 22, tagClass: .universal)
                    ) { bytes in
                        bytes.append(contentsOf: Data(formatter.string(from: value).utf8))
                    }
                }
            }

            try appendField(2, utf8String(options.appID))
            try appendField(3) { serializer in
                serializer.serializeRawBytes(attestedCertificateDER[...])
            }
            try appendField(4) { serializer in
                try serializer.serialize(ASN1OctetString(contentBytes: ArraySlice(options.clientHash)))
            }
            try appendField(5, utf8String(options.token))
            try appendField(6, utf8String(options.receiptType))
            try appendField(12, ia5Date(options.creationTime))
            if let riskMetric = options.riskMetric {
                if options.riskMetricAsString {
                    try appendField(17, utf8String(String(riskMetric)))
                } else {
                    try appendField(17) { serializer in
                        try serializer.serialize(riskMetric)
                    }
                }
            }
            if let notBefore = options.notBefore {
                try appendField(19, ia5Date(notBefore))
            }
            try appendField(21, ia5Date(options.expirationTime))
        }
        return Data(serializer.serializedBytes)
    }
}
