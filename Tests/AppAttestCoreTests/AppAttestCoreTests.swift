import Foundation
import Testing
import AppAttestCore

@Suite("AppAttestEnvironment")
struct EnvironmentTests {
    @Test func aaguidValues() {
        #expect(AppAttestEnvironment.development.aaguid == Data("appattestdevelop".utf8))
        #expect(AppAttestEnvironment.production.aaguid == Data("appattest".utf8) + Data(repeating: 0, count: 7))
        #expect(AppAttestEnvironment.development.aaguid.count == 16)
        #expect(AppAttestEnvironment.production.aaguid.count == 16)
    }

    @Test func aaguidRoundTrip() {
        for environment in AppAttestEnvironment.allCases {
            #expect(AppAttestEnvironment(aaguid: environment.aaguid) == environment)
        }
        #expect(AppAttestEnvironment(aaguid: Data(repeating: 0xff, count: 16)) == nil)
        #expect(AppAttestEnvironment(aaguid: Data()) == nil)
    }
}

@Suite("AppAttestKeyID")
struct KeyIDTests {
    @Test func rawBytesRoundTrip() {
        let bytes = Data((0..<32).map(UInt8.init))
        let keyID = AppAttestKeyID(rawBytes: bytes)
        #expect(keyID.rawBytes == bytes)
        #expect(AppAttestKeyID(base64EncodedString: keyID.base64EncodedString) == keyID)
    }

    @Test func invalidBase64() {
        #expect(AppAttestKeyID(base64EncodedString: "not base64!!").rawBytes == nil)
    }

    @Test func codableAsSingleString() throws {
        let keyID = AppAttestKeyID(rawBytes: Data(repeating: 7, count: 32))
        let encoded = try JSONEncoder().encode(keyID)
        #expect(String(decoding: encoded, as: UTF8.self) == "\"\(keyID.base64EncodedString)\"")
        let decoded = try JSONDecoder().decode(AppAttestKeyID.self, from: encoded)
        #expect(decoded == keyID)
    }
}

@Suite("Transport DTOs")
struct TransportDTOTests {
    @Test func attestationPayloadRoundTrip() throws {
        let payload = AttestationPayload(
            keyID: AppAttestKeyID(rawBytes: Data(repeating: 1, count: 32)),
            attestation: Data([0xa3, 0x01, 0x02])
        )
        let decoded = try JSONDecoder().decode(
            AttestationPayload.self,
            from: try JSONEncoder().encode(payload)
        )
        #expect(decoded == payload)
    }

    @Test func assertionPayloadRoundTrip() throws {
        let payload = AssertionPayload(
            keyID: AppAttestKeyID(rawBytes: Data(repeating: 2, count: 32)),
            assertion: Data([0xa2, 0x01]),
            clientData: Data("{\"challenge\":\"abc\"}".utf8)
        )
        let decoded = try JSONDecoder().decode(
            AssertionPayload.self,
            from: try JSONEncoder().encode(payload)
        )
        #expect(decoded == payload)
    }
}
