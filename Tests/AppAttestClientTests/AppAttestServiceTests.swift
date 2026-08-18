#if canImport(DeviceCheck)
import DeviceCheck
import Foundation
import Testing
@testable import AppAttestClient

/// A scriptable stand-in for `DCAppAttestService`.
final class MockBacking: AppAttestServiceBacking, @unchecked Sendable {
    var isSupported = true
    var generateKeyResult: Result<String, any Error> = .success("")
    var attestKeyResult: Result<Data, any Error> = .success(Data())
    var generateAssertionResult: Result<Data, any Error> = .success(Data())
    private(set) var attestedKeyID: String?
    private(set) var receivedClientDataHash: Data?

    func generateKey() async throws -> String {
        try generateKeyResult.get()
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        attestedKeyID = keyId
        receivedClientDataHash = clientDataHash
        return try attestKeyResult.get()
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        attestedKeyID = keyId
        receivedClientDataHash = clientDataHash
        return try generateAssertionResult.get()
    }
}

private func dcError(_ code: DCError.Code) -> NSError {
    NSError(domain: DCErrorDomain, code: code.rawValue)
}

@Suite("AppAttestService")
struct AppAttestServiceTests {
    @Test func passesValuesThrough() async throws {
        let backing = MockBacking()
        let keyIDString = Data(repeating: 3, count: 32).base64EncodedString()
        backing.generateKeyResult = .success(keyIDString)
        backing.attestKeyResult = .success(Data([1, 2, 3]))
        backing.generateAssertionResult = .success(Data([4, 5, 6]))
        let service = AppAttestService(backing: backing)

        #expect(service.isSupported)
        let keyID = try await service.generateKey()
        #expect(keyID.base64EncodedString == keyIDString)

        let hash = Data(repeating: 9, count: 32)
        let attestation = try await service.attestKey(keyID, clientDataHash: hash)
        #expect(attestation == Data([1, 2, 3]))
        #expect(backing.attestedKeyID == keyIDString)
        #expect(backing.receivedClientDataHash == hash)

        let assertion = try await service.generateAssertion(keyID, clientDataHash: hash)
        #expect(assertion == Data([4, 5, 6]))
    }

    @Test(arguments: [
        (DCError.Code.featureUnsupported, AppAttestClientError.Code.featureUnsupported),
        (DCError.Code.invalidInput, AppAttestClientError.Code.invalidInput),
        (DCError.Code.invalidKey, AppAttestClientError.Code.invalidKey),
        (DCError.Code.serverUnavailable, AppAttestClientError.Code.serverUnavailable),
        (DCError.Code.unknownSystemFailure, AppAttestClientError.Code.unknownSystemFailure),
    ])
    func mapsDCErrorCodes(dcCode: DCError.Code, expected: AppAttestClientError.Code) async {
        let backing = MockBacking()
        backing.generateKeyResult = .failure(dcError(dcCode))
        let service = AppAttestService(backing: backing)

        await #expect {
            _ = try await service.generateKey()
        } throws: { error in
            guard let clientError = error as? AppAttestClientError else { return false }
            return clientError.code == expected && clientError.underlyingError != nil
        }
    }

    @Test func mapsUnrelatedErrorsToUnknown() async {
        let backing = MockBacking()
        backing.attestKeyResult = .failure(URLError(.timedOut))
        let service = AppAttestService(backing: backing)

        await #expect {
            _ = try await service.attestKey(
                AppAttestKeyID(rawBytes: Data(repeating: 0, count: 32)),
                clientDataHash: Data()
            )
        } throws: { error in
            (error as? AppAttestClientError)?.code == .unknown
        }
    }
}
#endif
