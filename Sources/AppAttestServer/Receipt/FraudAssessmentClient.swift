import Foundation
import AppAttestCore

/// Errors returned by Apple's fraud-assessment endpoint.
public enum FraudAssessmentError: Error, Sendable, Hashable {
    /// HTTP 304 — you requested a refresh before the previous receipt's
    /// *Not Before* date (field 19). Wait and retry after that date.
    case notModified

    /// HTTP 400 — the receipt belongs to the other environment, or the
    /// request payload is missing or malformed.
    case badRequest

    /// HTTP 401 — the authentication token can't be verified or doesn't match
    /// the receipt.
    case unauthorized

    /// HTTP 404 — no data is available for the supplied receipt.
    case dataNotFound

    /// HTTP 429 — you sent too many requests; back off before retrying.
    case tooManyRequests

    /// HTTP 500/503 or any other status — a server-side failure.
    case serverError(statusCode: Int)

    /// The server responded with 200 but the body wasn't a Base64 receipt.
    case malformedResponse
}

/// Exchanges App Attest receipts with Apple's server to obtain the
/// fraud-assessment risk metric.
///
/// The risk metric is an approximate count of keys attested for your app on a
/// single device over the past 30 days. An unexpectedly high count can
/// indicate a compromised device serving many copies of your app.
///
/// ```swift
/// let client = FraudAssessmentClient(
///     environment: .production,
///     credentials: try AppStoreConnectCredentials(
///         keyIdentifier: "ABC123DEFG",
///         teamIdentifier: "A1B2C3D4E5",
///         privateKeyPEM: p8FileContents
///     )
/// )
///
/// let newReceiptData = try await client.refreshReceipt(storedReceipt)
/// let receipt = try await receiptVerifier.verify(
///     receipt: newReceiptData,
///     expectedPublicKey: storedPublicKey
/// )
/// print(receipt.riskMetric ?? 0)
/// // Store newReceiptData in place of the old receipt, and refresh again
/// // after receipt.notBefore but before receipt.expirationTime.
/// ```
///
/// Receipts are environment-bound: a development receipt can only be exchanged
/// with the development endpoint, and vice versa.
public struct FraudAssessmentClient: Sendable {
    /// The environment whose endpoint this client talks to.
    public let environment: AppAttestEnvironment

    /// The App Store Connect credentials used to sign request tokens.
    public let credentials: AppStoreConnectCredentials

    let httpClient: any AppAttestHTTPClient

    /// Creates a client.
    ///
    /// - Parameters:
    ///   - environment: The App Attest environment the receipts belong to.
    ///   - credentials: An App Store Connect key with DeviceCheck enabled.
    ///   - httpClient: The transport to use. Defaults to a `URLSession`-backed
    ///     client.
    public init(
        environment: AppAttestEnvironment,
        credentials: AppStoreConnectCredentials,
        httpClient: any AppAttestHTTPClient = URLSessionAppAttestHTTPClient()
    ) {
        self.environment = environment
        self.credentials = credentials
        self.httpClient = httpClient
    }

    /// The endpoint receipts are exchanged with.
    public var endpointURL: URL {
        switch environment {
        case .development:
            // Compiled-in constants are always valid URLs.
            // swift-format-ignore: NeverForceUnwrap
            return URL(string: "https://data-development.appattest.apple.com/v1/attestationData")!
        case .production:
            // swift-format-ignore: NeverForceUnwrap
            return URL(string: "https://data.appattest.apple.com/v1/attestationData")!
        }
    }

    /// Sends a receipt to Apple and returns the refreshed receipt.
    ///
    /// Verify the result with ``ReceiptVerifier`` and store it in place of the
    /// receipt you sent; the refreshed receipt carries the risk metric in
    /// field 17 and is the input for the next refresh.
    ///
    /// - Parameter receipt: A receipt extracted from an attestation object or
    ///   returned by a previous call.
    /// - Returns: The refreshed PKCS #7 receipt (decoded from Apple's Base64
    ///   response body).
    /// - Throws: ``FraudAssessmentError`` for endpoint errors, or any
    ///   transport error from the underlying HTTP client.
    public func refreshReceipt(_ receipt: Data) async throws -> Data {
        let token = try JWTSigner.token(credentials: credentials)
        let request = AppAttestHTTPRequest(
            url: endpointURL,
            headers: ["Authorization": token],
            body: receipt.base64EncodedData()
        )

        let response = try await httpClient.execute(request)
        switch response.statusCode {
        case 200:
            let body = String(decoding: response.body, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard let refreshed = Data(base64Encoded: body) else {
                throw FraudAssessmentError.malformedResponse
            }
            return refreshed
        case 304:
            throw FraudAssessmentError.notModified
        case 400:
            throw FraudAssessmentError.badRequest
        case 401:
            throw FraudAssessmentError.unauthorized
        case 404:
            throw FraudAssessmentError.dataNotFound
        case 429:
            throw FraudAssessmentError.tooManyRequests
        default:
            throw FraudAssessmentError.serverError(statusCode: response.statusCode)
        }
    }
}
