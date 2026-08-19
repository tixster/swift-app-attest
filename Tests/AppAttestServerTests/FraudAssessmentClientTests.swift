import Crypto
import Foundation
import Testing
@testable import AppAttestServer

/// Records the request and plays back a scripted response.
final class MockHTTPClient: AppAttestHTTPClient, @unchecked Sendable {
    var response = AppAttestHTTPResponse(statusCode: 200, body: Data())
    private(set) var lastRequest: AppAttestHTTPRequest?

    func execute(_ request: AppAttestHTTPRequest) async throws -> AppAttestHTTPResponse {
        lastRequest = request
        return response
    }
}

@Suite("FraudAssessmentClient")
struct FraudAssessmentClientTests {
    let credentials = DeviceCheckCredentials(
        keyIdentifier: "ABC123DEFG",
        teamIdentifier: "TEAM123456",
        privateKey: P256.Signing.PrivateKey()
    )

    func makeClient(
        environment: AppAttestEnvironment = .production,
        http: MockHTTPClient
    ) -> FraudAssessmentClient {
        FraudAssessmentClient(environment: environment, credentials: credentials, httpClient: http)
    }

    @Test func usesEnvironmentSpecificEndpoints() {
        let production = FraudAssessmentClient(environment: .production, credentials: credentials)
        let development = FraudAssessmentClient(environment: .development, credentials: credentials)
        #expect(production.endpointURL.absoluteString == "https://data.appattest.apple.com/v1/attestationData")
        #expect(
            development.endpointURL.absoluteString
                == "https://data-development.appattest.apple.com/v1/attestationData"
        )
    }

    @Test func sendsBase64BodyAndJWT() async throws {
        let http = MockHTTPClient()
        let refreshed = Data("refreshed-receipt".utf8)
        http.response = AppAttestHTTPResponse(
            statusCode: 200,
            body: refreshed.base64EncodedData()
        )
        let client = makeClient(http: http)
        let receipt = Data("original-receipt".utf8)

        let result = try await client.refreshReceipt(receipt)
        #expect(result == refreshed)

        let request = try #require(http.lastRequest)
        #expect(request.method == "POST")
        #expect(request.url == client.endpointURL)
        #expect(Data(base64Encoded: request.body) == receipt)

        let token = try #require(request.headers["Authorization"])
        try validateJWT(token)
    }

    @Test func toleratesWhitespaceAroundResponseBody() async throws {
        let http = MockHTTPClient()
        let refreshed = Data("refreshed".utf8)
        http.response = AppAttestHTTPResponse(
            statusCode: 200,
            body: Data((refreshed.base64EncodedString() + "\n").utf8)
        )
        let client = makeClient(http: http)

        #expect(try await client.refreshReceipt(Data([1])) == refreshed)
    }

    @Test(arguments: [
        (304, FraudAssessmentError.notModified),
        (400, FraudAssessmentError.badRequest),
        (401, FraudAssessmentError.unauthorized),
        (404, FraudAssessmentError.dataNotFound),
        (429, FraudAssessmentError.tooManyRequests),
        (500, FraudAssessmentError.serverError(statusCode: 500)),
        (503, FraudAssessmentError.serverError(statusCode: 503)),
    ])
    func mapsErrorStatuses(status: Int, expected: FraudAssessmentError) async {
        let http = MockHTTPClient()
        http.response = AppAttestHTTPResponse(statusCode: status, body: Data())
        let client = makeClient(http: http)

        await #expect(throws: expected) {
            _ = try await client.refreshReceipt(Data([1]))
        }
    }

    @Test func rejectsNonBase64SuccessBody() async {
        let http = MockHTTPClient()
        http.response = AppAttestHTTPResponse(statusCode: 200, body: Data("!!!".utf8))
        let client = makeClient(http: http)

        await #expect(throws: FraudAssessmentError.malformedResponse) {
            _ = try await client.refreshReceipt(Data([1]))
        }
    }

    // MARK: JWT

    private func validateJWT(_ token: String) throws {
        let parts = token.split(separator: ".")
        #expect(parts.count == 3)

        func decodeBase64URL(_ part: Substring) throws -> Data {
            var base64 = part
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            while base64.count % 4 != 0 {
                base64 += "="
            }
            return try #require(Data(base64Encoded: base64))
        }

        let header = try JSONSerialization.jsonObject(with: try decodeBase64URL(parts[0])) as? [String: Any]
        #expect(header?["alg"] as? String == "ES256")
        #expect(header?["kid"] as? String == credentials.keyIdentifier)

        let payload = try JSONSerialization.jsonObject(with: try decodeBase64URL(parts[1])) as? [String: Any]
        #expect(payload?["iss"] as? String == credentials.teamIdentifier)
        let issuedAt = try #require(payload?["iat"] as? Int)
        #expect(abs(Double(issuedAt) - Date().timeIntervalSince1970) < 60)

        // The signature must verify over "<header>.<payload>" with the raw
        // 64-byte representation.
        let signatureData = try decodeBase64URL(parts[2])
        #expect(signatureData.count == 64)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        #expect(credentials.privateKey.publicKey.isValidSignature(signature, for: signingInput))
    }
}
