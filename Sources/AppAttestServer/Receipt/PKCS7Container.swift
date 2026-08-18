import Foundation
import SwiftASN1

/// Minimal PKCS #7 / CMS `SignedData` reader used to extract the encapsulated
/// payload of an App Attest receipt.
///
/// Signature verification is delegated to swift-certificates' CMS support;
/// this type only pulls out the `eContent` bytes so the payload can be parsed
/// and so the signature can be checked against exactly those bytes.
enum PKCS7Container {
    /// Extracts the `eContent` octets of a BER/DER-encoded `SignedData` container.
    static func encapsulatedContent(of container: Data) throws(AppAttestReceiptError) -> Data {
        let root: ASN1Node
        do {
            root = try BER.parse([UInt8](container))
        } catch {
            throw AppAttestReceiptError.malformedReceipt(reason: "not valid BER: \(error)")
        }

        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        guard root.identifier == .sequence, case .constructed(let contentInfo) = root.content else {
            throw AppAttestReceiptError.malformedReceipt(reason: "container is not a SEQUENCE")
        }
        var contentInfoIterator = contentInfo.makeIterator()
        guard
            contentInfoIterator.next() != nil,
            let contentNode = contentInfoIterator.next(),
            contentNode.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
            case .constructed(let contentChildren) = contentNode.content,
            let signedDataNode = contentChildren.first(where: { _ in true })
        else {
            throw AppAttestReceiptError.malformedReceipt(reason: "missing SignedData content")
        }

        // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
        guard signedDataNode.identifier == .sequence, case .constructed(let signedData) = signedDataNode.content
        else {
            throw AppAttestReceiptError.malformedReceipt(reason: "SignedData is not a SEQUENCE")
        }
        var signedDataIterator = signedData.makeIterator()
        guard
            signedDataIterator.next() != nil,  // version
            signedDataIterator.next() != nil,  // digestAlgorithms
            let encapContentInfoNode = signedDataIterator.next(),
            encapContentInfoNode.identifier == .sequence,
            case .constructed(let encapContentInfo) = encapContentInfoNode.content
        else {
            throw AppAttestReceiptError.malformedReceipt(reason: "missing EncapsulatedContentInfo")
        }

        // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }
        var encapIterator = encapContentInfo.makeIterator()
        guard
            encapIterator.next() != nil,  // eContentType
            let eContentWrapper = encapIterator.next(),
            eContentWrapper.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
            case .constructed(let eContentChildren) = eContentWrapper.content,
            let octetStringNode = eContentChildren.first(where: { _ in true })
        else {
            throw AppAttestReceiptError.malformedReceipt(reason: "receipt has no encapsulated content")
        }

        return try octetStringContent(of: octetStringNode)
    }

    /// Returns the content of an OCTET STRING node, reassembling BER
    /// constructed (chunked) encodings.
    private static func octetStringContent(of node: ASN1Node) throws(AppAttestReceiptError) -> Data {
        guard node.identifier == .octetString else {
            throw AppAttestReceiptError.malformedReceipt(reason: "encapsulated content is not an OCTET STRING")
        }
        switch node.content {
        case .primitive(let bytes):
            return Data(bytes)
        case .constructed(let chunks):
            var combined = Data()
            for chunk in chunks {
                combined.append(try octetStringContent(of: chunk))
            }
            return combined
        }
    }
}
