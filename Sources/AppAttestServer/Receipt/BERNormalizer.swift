import Foundation
import SwiftASN1

/// Re-encodes a BER structure as strict DER.
///
/// Apple emits App Attest receipts in BER: constructed nodes use indefinite
/// lengths and the encapsulated payload is a chunked (constructed) OCTET
/// STRING. swift-certificates' CMS support parses strict DER only, so the
/// receipt is normalized before signature verification.
///
/// The transformation is signature-safe: the regions a CMS signature actually
/// covers — the SignedAttributes SET and the certificates — are required to
/// be DER already and are copied byte-for-byte, while the payload digest is
/// computed over the eContent octets, which chunk concatenation preserves
/// exactly.
enum BERNormalizer {

    /// Parses `data` as BER and returns its DER encoding.
    ///
    /// DER input is returned unchanged (DER is a subset of BER and the
    /// re-encoding is canonical).
    static func normalizeToDER(_ data: Data) throws -> Data {
        let root = try BER.parse([UInt8](data))
        var serializer = DER.Serializer()
        try append(root, to: &serializer)
        return Data(serializer.serializedBytes)
    }

    private static func append(_ node: ASN1Node, to serializer: inout DER.Serializer) throws {
        switch node.content {
        case .primitive(let bytes):
            serializer.appendPrimitiveNode(identifier: node.identifier) { buffer in
                buffer.append(contentsOf: bytes)
            }

        case .constructed(let children):
            // BER chunked strings collapse into a single primitive whose
            // content is the concatenation of the chunks' contents.
            if node.identifier == .octetString {
                let combined = try flattenOctetString(node)
                serializer.appendPrimitiveNode(identifier: .octetString) { buffer in
                    buffer.append(contentsOf: combined)
                }
                return
            }
            try serializer.appendConstructedNode(identifier: node.identifier) { serializer in
                for child in children {
                    try append(child, to: &serializer)
                }
            }
        }
    }

    private static func flattenOctetString(_ node: ASN1Node) throws -> [UInt8] {
        guard node.identifier == .octetString else {
            throw ASN1Error.invalidASN1Object(
                reason: "constructed OCTET STRING chunk has identifier \(node.identifier)"
            )
        }
        switch node.content {
        case .primitive(let bytes):
            return [UInt8](bytes)
        case .constructed(let chunks):
            var combined: [UInt8] = []
            for chunk in chunks {
                combined.append(contentsOf: try flattenOctetString(chunk))
            }
            return combined
        }
    }

}
