import Crypto
import Foundation
import SwiftASN1
import X509

/// Builds throwaway certificate chains shaped like Apple's App Attest chains.
enum TestCertificateFactory {
    static let nonceOID: ASN1ObjectIdentifier = [1, 2, 840, 113_635, 100, 8, 2]
    static let aclBlobOID: ASN1ObjectIdentifier = [1, 2, 840, 113_635, 100, 8, 6]

    struct Chain {
        let rootKey: P256.Signing.PrivateKey
        let root: Certificate
        let intermediateKey: P256.Signing.PrivateKey
        let intermediate: Certificate
        let leaf: Certificate
    }

    /// Wraps octets in Apple's `SEQUENCE { [1] { OCTET STRING } }` extension value.
    static func appleExtensionValue(wrapping octets: Data) throws -> ArraySlice<UInt8> {
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { sequence in
            try sequence.appendConstructedNode(
                identifier: ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            ) { tagged in
                try tagged.serialize(ASN1OctetString(contentBytes: ArraySlice(octets)))
            }
        }
        return serializer.serializedBytes[...]
    }

    static func name(_ commonName: String) throws -> DistinguishedName {
        try DistinguishedName {
            CommonName(commonName)
            OrganizationName("swift-app-attest tests")
        }
    }

    /// Creates a self-signed CA certificate.
    static func makeCA(
        commonName: String,
        key: P256.Signing.PrivateKey,
        notValidBefore: Date = Date().addingTimeInterval(-3600),
        notValidAfter: Date = Date().addingTimeInterval(3600)
    ) throws -> Certificate {
        let subject = try name(commonName)
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true))
            },
            issuerPrivateKey: Certificate.PrivateKey(key)
        )
    }

    /// Creates an intermediate CA issued by `issuer`.
    static func makeIntermediate(
        commonName: String,
        key: P256.Signing.PrivateKey,
        issuer: Certificate,
        issuerKey: P256.Signing.PrivateKey,
        notValidBefore: Date = Date().addingTimeInterval(-3600),
        notValidAfter: Date = Date().addingTimeInterval(3600)
    ) throws -> Certificate {
        try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: issuer.subject,
            subject: try name(commonName),
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true))
            },
            issuerPrivateKey: Certificate.PrivateKey(issuerKey)
        )
    }

    /// Creates a leaf certificate carrying Apple-style App Attest extensions.
    static func makeLeaf(
        commonName: String,
        publicKey: P256.Signing.PublicKey,
        issuer: Certificate,
        issuerKey: P256.Signing.PrivateKey,
        nonce: Data?,
        aclBlob: Data? = nil,
        notValidBefore: Date = Date().addingTimeInterval(-3600),
        notValidAfter: Date = Date().addingTimeInterval(3600)
    ) throws -> Certificate {
        var extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
        }
        if let nonce {
            try extensions.append(
                Certificate.Extension(
                    oid: nonceOID,
                    critical: false,
                    value: try appleExtensionValue(wrapping: nonce)
                )
            )
        }
        if let aclBlob {
            try extensions.append(
                Certificate.Extension(
                    oid: aclBlobOID,
                    critical: false,
                    value: try appleExtensionValue(wrapping: aclBlob)
                )
            )
        }
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: issuer.subject,
            subject: try name(commonName),
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(issuerKey)
        )
    }

    /// Builds root → intermediate → leaf, with the leaf carrying the given
    /// App Attest extension values.
    static func makeChain(
        leafPublicKey: P256.Signing.PublicKey,
        nonce: Data?,
        aclBlob: Data? = nil
    ) throws -> Chain {
        let rootKey = P256.Signing.PrivateKey()
        let root = try makeCA(commonName: "Test App Attest Root CA", key: rootKey)
        let intermediateKey = P256.Signing.PrivateKey()
        let intermediate = try makeIntermediate(
            commonName: "Test App Attest CA 1",
            key: intermediateKey,
            issuer: root,
            issuerKey: rootKey
        )
        let leaf = try makeLeaf(
            commonName: "Test credential certificate",
            publicKey: leafPublicKey,
            issuer: intermediate,
            issuerKey: intermediateKey,
            nonce: nonce,
            aclBlob: aclBlob
        )
        return Chain(
            rootKey: rootKey,
            root: root,
            intermediateKey: intermediateKey,
            intermediate: intermediate,
            leaf: leaf
        )
    }
}

extension Certificate {
    var derBytes: Data {
        get throws {
            var serializer = DER.Serializer()
            try serializer.serialize(self)
            return Data(serializer.serializedBytes)
        }
    }
}
