import Foundation

/// Errors thrown by the internal CBOR decoder.
enum CBORError: Error, Hashable {
    case truncated
    case trailingBytes
    case indefiniteLengthUnsupported
    case unsupportedItem(UInt8)
    case invalidUTF8
    case lengthOverflow
    case nestingTooDeep
}

/// A minimal CBOR (RFC 8949) value, covering the definite-length subset that
/// App Attest attestation and assertion objects use.
enum CBOR: Hashable, Sendable {
    case unsigned(UInt64)
    /// A negative integer; the represented value is `-1 - magnitude`.
    case negative(UInt64)
    case byteString(Data)
    case textString(String)
    case array([CBOR])
    case map([CBOR: CBOR])
    /// A simple value: 20 (false), 21 (true), 22 (null), 23 (undefined).
    case simple(UInt8)

    /// Decodes a single CBOR item that must span the whole input.
    static func decode(_ data: Data) throws(CBORError) -> CBOR {
        var reader = Reader(data)
        let value = try reader.decodeItem()
        guard reader.isAtEnd else { throw CBORError.trailingBytes }
        return value
    }

    // MARK: Accessors

    var textValue: String? {
        if case .textString(let value) = self { return value }
        return nil
    }

    var bytesValue: Data? {
        if case .byteString(let value) = self { return value }
        return nil
    }

    var arrayValue: [CBOR]? {
        if case .array(let value) = self { return value }
        return nil
    }

    var mapValue: [CBOR: CBOR]? {
        if case .map(let value) = self { return value }
        return nil
    }

    var unsignedValue: UInt64? {
        if case .unsigned(let value) = self { return value }
        return nil
    }

    /// Looks up a text key in a map value.
    subscript(key: String) -> CBOR? {
        mapValue?[.textString(key)]
    }
}

extension CBOR {
    /// A sequential decoder over a byte buffer. App Attest authenticator data
    /// can contain several CBOR items back to back (the COSE credential key
    /// followed by the extensions map), which is why this is exposed separately
    /// from ``CBOR/decode(_:)``.
    struct Reader {
        private let bytes: [UInt8]
        private(set) var offset: Int

        private static let maximumNestingDepth = 16

        init(_ data: Data) {
            self.bytes = [UInt8](data)
            self.offset = 0
        }

        var isAtEnd: Bool {
            offset >= bytes.count
        }

        /// Decodes the next item in the buffer.
        mutating func decodeItem() throws(CBORError) -> CBOR {
            try decodeItem(depth: 0)
        }

        /// Decodes the next item and also returns the exact bytes it occupied.
        mutating func decodeItemCapturingBytes() throws(CBORError) -> (item: CBOR, rawBytes: Data) {
            let start = offset
            let item = try decodeItem(depth: 0)
            return (item, Data(bytes[start..<offset]))
        }

        private mutating func decodeItem(depth: Int) throws(CBORError) -> CBOR {
            guard depth < Self.maximumNestingDepth else { throw CBORError.nestingTooDeep }

            let initialByte = try readByte()
            let majorType = initialByte >> 5
            let additional = initialByte & 0x1f

            switch majorType {
            case 0:
                return .unsigned(try readArgument(additional))
            case 1:
                return .negative(try readArgument(additional))
            case 2:
                let count = try readCount(additional)
                return .byteString(Data(try readBytes(count)))
            case 3:
                let count = try readCount(additional)
                guard let text = String(bytes: try readBytes(count), encoding: .utf8) else {
                    throw CBORError.invalidUTF8
                }
                return .textString(text)
            case 4:
                let count = try readCount(additional)
                try ensureRemaining(atLeast: count)
                var elements: [CBOR] = []
                elements.reserveCapacity(count)
                for _ in 0..<count {
                    elements.append(try decodeItem(depth: depth + 1))
                }
                return .array(elements)
            case 5:
                let count = try readCount(additional)
                try ensureRemaining(atLeast: count)
                var pairs: [CBOR: CBOR] = [:]
                pairs.reserveCapacity(count)
                for _ in 0..<count {
                    let key = try decodeItem(depth: depth + 1)
                    let value = try decodeItem(depth: depth + 1)
                    pairs[key] = value
                }
                return .map(pairs)
            case 6:
                // Tags carry no meaning for App Attest; skip the tag number and
                // decode the tagged item.
                _ = try readArgument(additional)
                return try decodeItem(depth: depth + 1)
            case 7:
                switch additional {
                case 20, 21, 22, 23:
                    return .simple(additional)
                default:
                    // Floats and other simple values never appear in App Attest objects.
                    throw CBORError.unsupportedItem(initialByte)
                }
            default:
                throw CBORError.unsupportedItem(initialByte)
            }
        }

        // MARK: Primitives

        private mutating func readByte() throws(CBORError) -> UInt8 {
            guard offset < bytes.count else { throw CBORError.truncated }
            defer { offset += 1 }
            return bytes[offset]
        }

        private mutating func readBytes(_ count: Int) throws(CBORError) -> ArraySlice<UInt8> {
            guard count <= bytes.count - offset else { throw CBORError.truncated }
            defer { offset += count }
            return bytes[offset..<offset + count]
        }

        /// Reads the argument encoded in the additional-information bits,
        /// following it into the 1/2/4/8-byte extended forms when needed.
        private mutating func readArgument(_ additional: UInt8) throws(CBORError) -> UInt64 {
            switch additional {
            case 0...23:
                return UInt64(additional)
            case 24:
                return UInt64(try readByte())
            case 25:
                let raw = try readBytes(2)
                return raw.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            case 26:
                let raw = try readBytes(4)
                return raw.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            case 27:
                let raw = try readBytes(8)
                return raw.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            case 31:
                throw CBORError.indefiniteLengthUnsupported
            default:
                throw CBORError.unsupportedItem(additional)
            }
        }

        /// Reads a length argument and bounds-checks it against the remaining input.
        private mutating func readCount(_ additional: UInt8) throws(CBORError) -> Int {
            let value = try readArgument(additional)
            guard let count = Int(exactly: value) else { throw CBORError.lengthOverflow }
            return count
        }

        /// Guards collection counts against maliciously large headers: every
        /// element needs at least one byte of input.
        private func ensureRemaining(atLeast count: Int) throws(CBORError) {
            guard count <= bytes.count - offset else { throw CBORError.truncated }
        }
    }
}
