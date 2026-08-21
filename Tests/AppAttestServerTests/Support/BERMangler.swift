import Foundation
import SwiftASN1
@testable import AppAttestServer

/// Re-encodes a DER CMS receipt the way Apple's BER encoder does: the
/// container spine (ContentInfo → SignedData → EncapsulatedContentInfo)
/// switches to indefinite lengths, and the `eContent` OCTET STRING is split
/// into constructed chunks. The signed regions are copied byte-for-byte, so
/// the mangled receipt stays cryptographically valid.
enum BERMangler {

    static func mangle(_ der: Data) throws -> Data {
        let root = try BER.parse([UInt8](der))

        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
        guard case .constructed(let contentInfo) = root.content else {
            throw ASN1Error.invalidASN1Object(reason: "ContentInfo is not constructed")
        }
        let contentInfoChildren = Array(contentInfo)
        guard contentInfoChildren.count == 2,
              case .constructed(let contentWrapper) = contentInfoChildren[1].content,
              let signedDataNode = Array(contentWrapper).first,
              case .constructed(let signedData) = signedDataNode.content else {
            throw ASN1Error.invalidASN1Object(reason: "missing SignedData")
        }

        // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
        let signedDataChildren = Array(signedData)
        guard signedDataChildren.count >= 3,
              case .constructed(let encapContentInfo) = signedDataChildren[2].content else {
            throw ASN1Error.invalidASN1Object(reason: "missing EncapsulatedContentInfo")
        }
        let encapChildren = Array(encapContentInfo)
        guard encapChildren.count == 2,
              case .constructed(let eContentWrapper) = encapChildren[1].content,
              let octetStringNode = Array(eContentWrapper).first,
              case .primitive(let payload) = octetStringNode.content else {
            throw ASN1Error.invalidASN1Object(reason: "missing primitive eContent")
        }

        // The payload split into two chunks inside an indefinite-length
        // constructed OCTET STRING (tag 0x24).
        let half = payload.count / 2
        var chunkedPayload = Data([0x24, 0x80])
        chunkedPayload += primitiveOctetString(Data(payload.prefix(half)))
        chunkedPayload += primitiveOctetString(Data(payload.dropFirst(half)))
        chunkedPayload += Data([0x00, 0x00])

        let mangledEncap = indefinite(
            tag: 0x30,
            content: Data(encapChildren[0].encodedBytes) + indefinite(tag: 0xA0, content: chunkedPayload)
        )

        var signedDataContent = Data(signedDataChildren[0].encodedBytes)
        signedDataContent += Data(signedDataChildren[1].encodedBytes)
        signedDataContent += mangledEncap
        for child in signedDataChildren.dropFirst(3) {
            signedDataContent += Data(child.encodedBytes)
        }

        return indefinite(
            tag: 0x30,
            content: Data(contentInfoChildren[0].encodedBytes)
                + indefinite(tag: 0xA0, content: indefinite(tag: 0x30, content: signedDataContent))
        )
    }

    private static func indefinite(tag: UInt8, content: Data) -> Data {
        Data([tag, 0x80]) + content + Data([0x00, 0x00])
    }

    private static func primitiveOctetString(_ content: Data) -> Data {
        Data([0x04]) + encodedLength(content.count) + content
    }

    private static func encodedLength(_ length: Int) -> Data {
        guard length >= 0x80 else { return Data([UInt8(length)]) }
        var bytes: [UInt8] = []
        var remaining = length
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }

}
