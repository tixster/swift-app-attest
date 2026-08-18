import Foundation

/// An HTTP request issued by ``FraudAssessmentClient``.
public struct AppAttestHTTPRequest: Sendable, Hashable {
    /// The request URL.
    public let url: URL

    /// The HTTP method; always `POST` for the fraud-assessment endpoint.
    public let method: String

    /// The request headers, including the `Authorization` JWT.
    public let headers: [String: String]

    /// The request body.
    public let body: Data

    /// Creates a request.
    public init(url: URL, method: String = "POST", headers: [String: String], body: Data) {
        self.url = url
        self.method = method
        self.headers = headers
        self.body = body
    }
}

/// An HTTP response consumed by ``FraudAssessmentClient``.
public struct AppAttestHTTPResponse: Sendable, Hashable {
    /// The HTTP status code.
    public let statusCode: Int

    /// The response body.
    public let body: Data

    /// Creates a response.
    public init(statusCode: Int, body: Data) {
        self.statusCode = statusCode
        self.body = body
    }
}

/// The transport abstraction used by ``FraudAssessmentClient``.
///
/// A `URLSession`-backed implementation, ``URLSessionAppAttestHTTPClient``, is
/// used by default. Server applications that prefer AsyncHTTPClient (or any
/// other stack) can conform their client and pass it to
/// ``FraudAssessmentClient/init(environment:credentials:httpClient:)``.
public protocol AppAttestHTTPClient: Sendable {
    /// Executes a request and returns the response.
    ///
    /// Implementations should throw for transport-level failures and return a
    /// response for any HTTP status; status handling is the caller's job.
    func execute(_ request: AppAttestHTTPRequest) async throws -> AppAttestHTTPResponse
}
