import Foundation

/// A tiny CBOR encoder for building test fixtures.
///
/// All self-references go through `Array`, so the enum needs no `indirect`
/// boxing — and the map payload is a named struct rather than a tuple of
/// `TestCBOR`, because a self-referential tuple payload trips a spurious
/// "circular reference" error in the Swift 6.1 compiler.
enum TestCBOR {
    struct MapEntry {
        var key: TestCBOR
        var value: TestCBOR
    }

    case unsigned(UInt64)
    /// Encodes the CBOR negative integer `-1 - magnitude`.
    case negative(UInt64)
    case bytes(Data)
    case text(String)
    case array([TestCBOR])
    /// Ordered key-value pairs, encoded in the given order.
    case mapEntries([MapEntry])

    /// Ordered key-value pairs, keeping tuple syntax at call sites.
    static func map(_ pairs: [(TestCBOR, TestCBOR)]) -> TestCBOR {
        .mapEntries(pairs.map { MapEntry(key: $0.0, value: $0.1) })
    }

    /// Convenience for small signed integers (COSE uses -1, -2, -3, -7).
    static func int(_ value: Int) -> TestCBOR {
        value >= 0 ? .unsigned(UInt64(value)) : .negative(UInt64(-1 - value))
    }

    var encoded: Data {
        switch self {
        case .unsigned(let value):
            return Self.header(major: 0, argument: value)
        case .negative(let magnitude):
            return Self.header(major: 1, argument: magnitude)
        case .bytes(let data):
            return Self.header(major: 2, argument: UInt64(data.count)) + data
        case .text(let string):
            let utf8 = Data(string.utf8)
            return Self.header(major: 3, argument: UInt64(utf8.count)) + utf8
        case .array(let elements):
            return elements.reduce(Self.header(major: 4, argument: UInt64(elements.count))) {
                $0 + $1.encoded
            }
        case .mapEntries(let entries):
            return entries.reduce(Self.header(major: 5, argument: UInt64(entries.count))) {
                $0 + $1.key.encoded + $1.value.encoded
            }
        }
    }

    private static func header(major: UInt8, argument: UInt64) -> Data {
        switch argument {
        case 0..<24:
            return Data([major << 5 | UInt8(argument)])
        case 24...UInt64(UInt8.max):
            return Data([major << 5 | 24, UInt8(argument)])
        case (UInt64(UInt8.max) + 1)...UInt64(UInt16.max):
            return Data([major << 5 | 25]) + argument.bigEndianBytes.suffix(2)
        case (UInt64(UInt16.max) + 1)...UInt64(UInt32.max):
            return Data([major << 5 | 26]) + argument.bigEndianBytes.suffix(4)
        default:
            return Data([major << 5 | 27]) + argument.bigEndianBytes
        }
    }
}

extension UInt64 {
    var bigEndianBytes: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}

extension UInt32 {
    var bigEndianBytes: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}
