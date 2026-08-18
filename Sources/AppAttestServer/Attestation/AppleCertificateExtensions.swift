import Foundation
import SwiftASN1
import X509

/// Helpers for the Apple-specific X.509 extensions found in App Attest
/// credential certificates.
enum AppleCertificateExtensions {
    /// OID of the nonce extension in the credential certificate.
    static let nonceOID: ASN1ObjectIdentifier = [1, 2, 840, 113_635, 100, 8, 2]

    /// OID of the macOS key access-control policy extension (`aclBlob`).
    static let accessControlPolicyOID: ASN1ObjectIdentifier = [1, 2, 840, 113_635, 100, 8, 6]

    /// The expected `aclBlob` value: the encoded hash of the access policy for
    /// an attested key on macOS with SIP and Full Security mode enabled. Apple
    /// documents that keys should only be trusted for this exact value.
    static let expectedAccessControlPolicy = Data(
        base64Encoded: "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB"
    )!

    /// Extracts the single octet string wrapped inside one of Apple's
    /// `SEQUENCE { [1] { OCTET STRING } }` extension values.
    ///
    /// Apple describes both the nonce and the `aclBlob` extensions as "a
    /// DER-encoded ASN.1 sequence [containing] a single octet string". The
    /// octet string sits inside a context-specific constructed tag, so this
    /// walks one level of tagging to find it.
    static func singleOctetString(inExtensionValue value: ArraySlice<UInt8>) throws -> Data {
        let root = try DER.parse(Array(value))
        guard root.identifier == .sequence, case .constructed(let children) = root.content else {
            throw ASN1Error.unexpectedFieldType(root.identifier)
        }
        for child in children {
            if child.identifier == .octetString, case .primitive(let bytes) = child.content {
                return Data(bytes)
            }
            if child.identifier.tagClass == .contextSpecific, case .constructed(let inner) = child.content {
                for node in inner
                where node.identifier == .octetString {
                    if case .primitive(let bytes) = node.content {
                        return Data(bytes)
                    }
                }
            }
        }
        throw ASN1Error.invalidASN1Object(reason: "no octet string found in Apple extension value")
    }

    /// Returns the nonce embedded in a credential certificate, or `nil` when
    /// the extension is absent.
    static func nonce(in certificate: Certificate) throws -> Data? {
        guard let ext = certificate.extensions[oid: nonceOID] else { return nil }
        return try singleOctetString(inExtensionValue: ext.value)
    }

    /// Returns the macOS access-control policy blob, or `nil` when the
    /// extension is absent (all non-macOS attestations).
    static func accessControlPolicy(in certificate: Certificate) throws -> Data? {
        guard let ext = certificate.extensions[oid: accessControlPolicyOID] else { return nil }
        return try singleOctetString(inExtensionValue: ext.value)
    }
}
