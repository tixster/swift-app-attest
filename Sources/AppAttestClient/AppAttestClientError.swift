#if canImport(DeviceCheck)
import DeviceCheck
import Foundation

/// A typed error thrown by ``AppAttestService``.
///
/// Wraps the `DCError` codes produced by `DCAppAttestService` and preserves the
/// original error for diagnostics.
public struct AppAttestClientError: Error, Sendable {
    /// The classified failure reason.
    public enum Code: Sendable, Hashable {
        /// App Attest isn't available on this device.
        ///
        /// Check ``AppAttestService/isSupported`` before calling any other API.
        /// Simulators and some older devices don't support App Attest; fall back
        /// to other protections in that case.
        case featureUnsupported

        /// An input was malformed — for example, an empty client data hash or a
        /// key identifier that isn't valid Base64.
        case invalidInput

        /// The key identifier doesn't refer to a usable App Attest key.
        ///
        /// The key may have been removed (App Attest keys don't survive app
        /// re-installs, backup restores, or device transfers). Discard the stored
        /// identifier, generate a new key, and run attestation again.
        case invalidKey

        /// Apple's attestation server couldn't be reached or returned an error.
        ///
        /// This is transient; retry with backoff.
        case serverUnavailable

        /// An unexpected system failure occurred.
        case unknownSystemFailure

        /// The underlying error wasn't a recognized `DCError`.
        case unknown
    }

    /// The classified failure reason.
    public let code: Code

    /// The original error thrown by DeviceCheck, useful for logging.
    public let underlyingError: (any Error)?

    /// Creates an error with an explicit code.
    public init(code: Code, underlyingError: (any Error)? = nil) {
        self.code = code
        self.underlyingError = underlyingError
    }

    /// Classifies an arbitrary error thrown by `DCAppAttestService`.
    public init(wrapping error: any Error) {
        let code: Code
        switch (error as NSError).domain == DCErrorDomain ? DCError.Code(rawValue: (error as NSError).code) : nil {
        case .featureUnsupported: code = .featureUnsupported
        case .invalidInput: code = .invalidInput
        case .invalidKey: code = .invalidKey
        case .serverUnavailable: code = .serverUnavailable
        case .unknownSystemFailure: code = .unknownSystemFailure
        default: code = .unknown
        }
        self.init(code: code, underlyingError: error)
    }
}

extension AppAttestClientError: CustomStringConvertible {
    public var description: String {
        var text = "AppAttestClientError(\(code))"
        if let underlyingError {
            text += " underlying: \(underlyingError)"
        }
        return text
    }
}
#endif
