import Foundation
import SwiftASN1
import X509

/// Errors thrown while parsing or verifying App Attest receipts.
public enum AppAttestReceiptError: Error, Sendable, Hashable {
    /// The PKCS #7 signature couldn't be verified against the Apple root.
    case invalidSignature(reason: String)

    /// The PKCS #7 container or its ASN.1 payload couldn't be parsed.
    case malformedReceipt(reason: String)

    /// A required payload field is missing.
    case missingField(Int)

    /// A payload field's contents couldn't be decoded.
    case malformedField(Int)

    /// Field 2 doesn't match the configured App ID.
    case appIDMismatch(expected: String, received: String)

    /// Field 3 doesn't contain the attested public key you supplied.
    case publicKeyMismatch

    /// The receipt's creation time (field 12) is older than allowed.
    case receiptTooOld(creationTime: Date)

    /// The receipt's expiration time (field 21) has passed.
    case receiptExpired(expirationTime: Date)
}

/// A parsed and decoded App Attest receipt payload.
///
/// Receipts are PKCS #7 containers, structurally similar to App Store
/// receipts: a signature, a certificate chain, and an ASN.1 payload made of
/// numbered attribute fields.
public struct AppAttestReceipt: Sendable, Hashable {
    /// The kind of receipt, from field 6.
    public enum ReceiptType: String, Sendable, Hashable {
        /// The receipt that accompanies an attestation object. Carries no risk metric.
        case attest = "ATTEST"

        /// A receipt returned by Apple's server. Carries the risk metric.
        case receipt = "RECEIPT"
    }

    /// One raw attribute field of the payload.
    public struct Field: Sendable, Hashable {
        /// The field number.
        public let type: Int

        /// The field version.
        public let version: Int

        /// The field contents (the octet-string body; itself often a
        /// DER-encoded primitive).
        public let value: Data
    }

    /// All payload fields, in the order they appear, including ones this type
    /// doesn't model.
    public let fields: [Field]

    /// The App ID of your app (field 2).
    public let appID: String

    /// The DER-encoded attestation certificate carrying the attested public
    /// key (field 3).
    public let attestedCertificateData: Data

    /// The client hash (field 4).
    public let clientHash: Data

    /// An opaque token (field 5).
    public let token: String

    /// The receipt type (field 6).
    public let receiptType: ReceiptType

    /// When Apple created the receipt (field 12).
    public let creationTime: Date

    /// The approximate number of attested keys for this device over the past
    /// 30 days (field 17). Only ``ReceiptType-swift.enum/receipt`` receipts
    /// carry it.
    public let riskMetric: Int?

    /// Don't request a refreshed receipt before this date (field 19).
    public let notBefore: Date?

    /// The receipt can't be exchanged after this date (field 21).
    public let expirationTime: Date

    /// The attestation certificate from field 3, decoded.
    public func attestedCertificate() throws(AppAttestReceiptError) -> Certificate {
        do {
            return try Certificate(derEncoded: [UInt8](attestedCertificateData))
        } catch {
            throw AppAttestReceiptError.malformedField(3)
        }
    }

    /// Parses a decoded PKCS #7 payload into typed fields.
    ///
    /// The payload is a `SET OF SEQUENCE { type INTEGER, version INTEGER,
    /// value OCTET STRING }`.
    public init(payload: Data) throws(AppAttestReceiptError) {
        let rootNode: ASN1Node
        do {
            rootNode = try BER.parse([UInt8](payload))
        } catch {
            throw AppAttestReceiptError.malformedReceipt(reason: "payload is not valid ASN.1: \(error)")
        }
        guard rootNode.identifier == .set, case .constructed(let attributes) = rootNode.content else {
            throw AppAttestReceiptError.malformedReceipt(reason: "payload is not a SET")
        }

        var fields: [Field] = []
        for attribute in attributes {
            guard let field = try? Self.parseAttribute(attribute) else {
                throw AppAttestReceiptError.malformedReceipt(reason: "undecodable attribute")
            }
            fields.append(field)
        }
        self.fields = fields

        func fieldValue(_ type: Int) -> Data? {
            fields.first(where: { $0.type == type })?.value
        }
        func required(_ type: Int) throws(AppAttestReceiptError) -> Data {
            guard let value = fieldValue(type) else { throw AppAttestReceiptError.missingField(type) }
            return value
        }
        func string(_ type: Int) throws(AppAttestReceiptError) -> String {
            guard let string = Self.decodeString(try required(type)) else {
                throw AppAttestReceiptError.malformedField(type)
            }
            return string
        }
        func date(_ type: Int) throws(AppAttestReceiptError) -> Date {
            guard let date = Self.decodeDate(try required(type)) else {
                throw AppAttestReceiptError.malformedField(type)
            }
            return date
        }

        self.appID = try string(2)
        self.attestedCertificateData = Self.decodeOctets(try required(3))
        self.clientHash = Self.decodeOctets(try required(4))
        self.token = try string(5)
        guard let receiptType = ReceiptType(rawValue: try string(6)) else {
            throw AppAttestReceiptError.malformedField(6)
        }
        self.receiptType = receiptType
        self.creationTime = try date(12)
        if let metric = fieldValue(17) {
            guard let value = Self.decodeInteger(metric) else {
                throw AppAttestReceiptError.malformedField(17)
            }
            self.riskMetric = value
        } else {
            self.riskMetric = nil
        }
        self.notBefore = fieldValue(19) != nil ? try date(19) : nil
        self.expirationTime = try date(21)
    }

    // MARK: Attribute decoding

    private static func parseAttribute(_ node: ASN1Node) throws(AppAttestReceiptError) -> Field {
        guard node.identifier == .sequence, case .constructed(let children) = node.content else {
            throw AppAttestReceiptError.malformedReceipt(reason: "attribute is not a SEQUENCE")
        }
        var iterator = children.makeIterator()
        guard
            let typeNode = iterator.next(),
            let versionNode = iterator.next(),
            let valueNode = iterator.next(),
            valueNode.identifier == .octetString,
            case .primitive(let valueBytes) = valueNode.content,
            let type = try? Int(derEncoded: typeNode),
            let version = try? Int(derEncoded: versionNode)
        else {
            throw AppAttestReceiptError.malformedReceipt(reason: "attribute has unexpected structure")
        }
        return Field(type: type, version: version, value: Data(valueBytes))
    }

    /// Decodes a field body that contains a DER string (UTF8String or IA5String).
    static func decodeString(_ value: Data) -> String? {
        guard let node = try? DER.parse([UInt8](value)), case .primitive(let bytes) = node.content else {
            return nil
        }
        switch node.identifier {
        case .utf8String, ASN1Identifier(tagWithNumber: 22, tagClass: .universal):  // IA5String
            return String(decoding: bytes, as: UTF8.self)
        default:
            return nil
        }
    }

    /// Decodes a field body that contains an RFC 3339 date in a DER string.
    static func decodeDate(_ value: Data) -> Date? {
        guard let string = decodeString(value) else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: string) {
            return date
        }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: string)
    }

    /// Decodes a field body that contains an integer — either a DER INTEGER or
    /// a DER string of digits (Apple represents the risk metric as a string).
    static func decodeInteger(_ value: Data) -> Int? {
        if let node = try? DER.parse([UInt8](value)), let integer = try? Int(derEncoded: node) {
            return integer
        }
        return decodeString(value).flatMap(Int.init)
    }

    /// Unwraps a field body that may itself be a DER OCTET STRING, returning
    /// raw bytes otherwise (field 3 stores certificate DER directly).
    static func decodeOctets(_ value: Data) -> Data {
        if let node = try? DER.parse([UInt8](value)),
            node.identifier == .octetString,
            case .primitive(let bytes) = node.content
        {
            return Data(bytes)
        }
        return value
    }
}
