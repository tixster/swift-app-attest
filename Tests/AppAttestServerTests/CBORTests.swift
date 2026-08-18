import Foundation
import Testing
@testable import AppAttestServer

@Suite("CBOR decoder")
struct CBORTests {
    @Test func decodesUnsignedIntegers() throws {
        #expect(try CBOR.decode(Data([0x00])) == .unsigned(0))
        #expect(try CBOR.decode(Data([0x17])) == .unsigned(23))
        #expect(try CBOR.decode(Data([0x18, 0x18])) == .unsigned(24))
        #expect(try CBOR.decode(Data([0x19, 0x01, 0x00])) == .unsigned(256))
        #expect(try CBOR.decode(Data([0x1a, 0x00, 0x01, 0x00, 0x00])) == .unsigned(65536))
        #expect(
            try CBOR.decode(Data([0x1b, 0, 0, 0, 1, 0, 0, 0, 0])) == .unsigned(4_294_967_296)
        )
    }

    @Test func decodesNegativeIntegers() throws {
        // -1 and -500
        #expect(try CBOR.decode(Data([0x20])) == .negative(0))
        #expect(try CBOR.decode(Data([0x39, 0x01, 0xf3])) == .negative(499))
    }

    @Test func decodesStringsAndBytes() throws {
        #expect(try CBOR.decode(Data([0x63, 0x66, 0x6d, 0x74])) == .textString("fmt"))
        #expect(try CBOR.decode(Data([0x42, 0xde, 0xad])) == .byteString(Data([0xde, 0xad])))
    }

    @Test func decodesNestedStructures() throws {
        let encoded = TestCBOR.map([
            (.text("fmt"), .text("apple-appattest")),
            (
                .text("attStmt"),
                .map([
                    (.text("x5c"), .array([.bytes(Data([1])), .bytes(Data([2]))])),
                    (.text("receipt"), .bytes(Data([3, 4]))),
                ])
            ),
        ]).encoded

        let decoded = try CBOR.decode(encoded)
        #expect(decoded["fmt"]?.textValue == "apple-appattest")
        #expect(decoded["attStmt"]?["x5c"]?.arrayValue?.count == 2)
        #expect(decoded["attStmt"]?["receipt"]?.bytesValue == Data([3, 4]))
    }

    @Test func decodesTaggedItemsTransparently() throws {
        // Tag 1 (epoch time) around unsigned 100.
        #expect(try CBOR.decode(Data([0xc1, 0x18, 0x64])) == .unsigned(100))
    }

    @Test func decodesSimpleValues() throws {
        #expect(try CBOR.decode(Data([0xf4])) == .simple(20))
        #expect(try CBOR.decode(Data([0xf5])) == .simple(21))
    }

    @Test func rejectsIndefiniteLength() {
        #expect(throws: CBORError.indefiniteLengthUnsupported) {
            _ = try CBOR.decode(Data([0x5f, 0x41, 0x00, 0xff]))
        }
    }

    @Test func rejectsTrailingBytes() {
        #expect(throws: CBORError.trailingBytes) {
            _ = try CBOR.decode(Data([0x00, 0x00]))
        }
    }

    @Test func rejectsTruncatedInput() {
        #expect(throws: CBORError.truncated) {
            _ = try CBOR.decode(Data([0x62, 0x61]))  // text of length 2, one byte present
        }
        #expect(throws: CBORError.truncated) {
            _ = try CBOR.decode(Data([0x19, 0x01]))  // 2-byte argument, one byte present
        }
    }

    @Test func rejectsOversizedCollectionHeaders() {
        // An array claiming 2^32 elements in a 5-byte input must fail fast
        // instead of reserving memory.
        #expect(throws: CBORError.truncated) {
            _ = try CBOR.decode(Data([0x9a, 0xff, 0xff, 0xff, 0xff]))
        }
    }

    @Test func rejectsFloats() {
        #expect(throws: CBORError.self) {
            _ = try CBOR.decode(Data([0xfb, 0, 0, 0, 0, 0, 0, 0, 0]))
        }
    }

    @Test func rejectsDeepNesting() {
        var encoded = Data([0x00])
        for _ in 0..<64 {
            encoded = Data([0x81]) + encoded  // wrap in single-element arrays
        }
        #expect(throws: CBORError.nestingTooDeep) {
            _ = try CBOR.decode(encoded)
        }
    }

    @Test func readerDecodesConsecutiveItems() throws {
        let first = TestCBOR.map([(.int(1), .int(2))]).encoded
        let second = TestCBOR.text("extensions").encoded
        var reader = CBOR.Reader(first + second)

        let (item, raw) = try reader.decodeItemCapturingBytes()
        #expect(raw == first)
        #expect(item.mapValue?[.unsigned(1)] == .unsigned(2))
        #expect(try reader.decodeItem() == .textString("extensions"))
        #expect(reader.isAtEnd)
    }
}

@Suite("AuthenticatorData")
struct AuthenticatorDataTests {
    @Test func parsesAssertionStyleData() throws {
        var raw = Data(repeating: 0xaa, count: 32)
        raw.append(0x00)
        raw += UInt32(41).bigEndianBytes

        let parsed = try AuthenticatorData(parsing: raw)
        #expect(parsed.rpIdHash == Data(repeating: 0xaa, count: 32))
        #expect(parsed.signCount == 41)
        #expect(parsed.aaguid == nil)
        #expect(parsed.credentialID == nil)
        #expect(parsed.extensions == nil)
        #expect(parsed.rawBytes == raw)
    }

    @Test func parsesAttestationStyleData() throws {
        var options = AttestationFixture.Options()
        options.counter = 0
        let x963 = Data([0x04]) + Data(repeating: 1, count: 64)
        let keyID = Data(repeating: 2, count: 32)
        let raw = AttestationFixture.makeAuthenticatorData(
            options: options,
            publicKeyX963: x963,
            keyIDBytes: keyID
        )

        let parsed = try AuthenticatorData(parsing: raw)
        #expect(parsed.flags.contains(.attestedCredentialData))
        #expect(parsed.flags.contains(.extensionData))
        #expect(parsed.aaguid == AppAttestEnvironment.development.aaguid)
        #expect(parsed.credentialID == keyID)
        #expect(parsed.credentialPublicKey == AttestationFixture.coseKey(x963: x963))
        #expect(parsed.extensions?.validationCategory == .appStore)
        #expect(parsed.extensions?.bundleVersion == "1.2.3")
    }

    @Test func parsesShortExtensionKeyNames() throws {
        var raw = Data(repeating: 0xbb, count: 32)
        raw.append(0x80)
        raw += UInt32(1).bigEndianBytes
        raw += TestCBOR.map([
            (.text("validationCategory"), .unsigned(2)),
            (.text("bundleVersion"), .text("9.9")),
        ]).encoded

        let parsed = try AuthenticatorData(parsing: raw)
        #expect(parsed.extensions?.validationCategory == .testFlight)
        #expect(parsed.extensions?.bundleVersion == "9.9")
    }

    @Test func rejectsTruncatedInputs() {
        #expect(throws: AppAttestVerificationError.self) {
            _ = try AuthenticatorData(parsing: Data(repeating: 0, count: 36))
        }

        // AT flag set but no attested credential data.
        var raw = Data(repeating: 0, count: 32)
        raw.append(0x40)
        raw += UInt32(0).bigEndianBytes
        #expect(throws: AppAttestVerificationError.self) {
            _ = try AuthenticatorData(parsing: raw)
        }
    }

    @Test func rejectsEDFlagWithoutExtensions() {
        var raw = Data(repeating: 0, count: 32)
        raw.append(0x80)
        raw += UInt32(0).bigEndianBytes
        #expect(throws: AppAttestVerificationError.self) {
            _ = try AuthenticatorData(parsing: raw)
        }
    }

    @Test func rejectsTrailingGarbage() {
        var raw = Data(repeating: 0, count: 32)
        raw.append(0x00)
        raw += UInt32(0).bigEndianBytes
        raw += TestCBOR.text("unexpected").encoded
        #expect(throws: AppAttestVerificationError.self) {
            _ = try AuthenticatorData(parsing: raw)
        }
    }
}
