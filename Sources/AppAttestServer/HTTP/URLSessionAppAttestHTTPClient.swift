import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The default ``AppAttestHTTPClient`` backed by `URLSession`.
///
/// On Linux, FoundationNetworking's async `data(for:)` is used directly. On
/// Darwin the same API carries iOS 15/macOS 12 availability, so a
/// continuation-wrapped `dataTask` keeps the package's iOS 14/macOS 11 floor.
public struct URLSessionAppAttestHTTPClient: AppAttestHTTPClient {
    /// The session requests are issued on.
    public let session: URLSession

    /// Creates a client.
    ///
    /// - Parameter session: The session to use. Defaults to `URLSession.shared`.
    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func execute(_ request: AppAttestHTTPRequest) async throws -> AppAttestHTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = request.body
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }

        #if canImport(FoundationNetworking)
        let (data, response) = try await session.data(for: urlRequest)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        return AppAttestHTTPResponse(statusCode: httpResponse.statusCode, body: data)
        #else
        return try await withCheckedThrowingContinuation { continuation in
            let task = session.dataTask(with: urlRequest) { data, response, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let httpResponse = response as? HTTPURLResponse else {
                    continuation.resume(throwing: URLError(.badServerResponse))
                    return
                }
                continuation.resume(
                    returning: AppAttestHTTPResponse(
                        statusCode: httpResponse.statusCode,
                        body: data ?? Data()
                    )
                )
            }
            task.resume()
        }
        #endif
    }
}
