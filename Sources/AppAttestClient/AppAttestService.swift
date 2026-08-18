#if canImport(DeviceCheck)
import CryptoKit
import DeviceCheck
import Foundation

/// A thin async wrapper around `DCAppAttestService`.
///
/// The wrapper mirrors the DeviceCheck API one-to-one and adds typed errors
/// (``AppAttestClientError``) plus the shared ``AppAttestKeyID`` type, so the
/// values you send to the server line up with what `AppAttestServer` expects.
///
/// A typical enrollment flow:
///
/// ```swift
/// let service = AppAttestService.shared
/// guard service.isSupported else { /* fall back */ }
///
/// let challenge: Data = try await api.fetchChallenge()
/// let keyID = try await service.generateKey()
/// let attestation = try await service.attestKey(keyID, challenge: challenge)
/// try await api.enroll(AttestationPayload(keyID: keyID, attestation: attestation))
/// ```
///
/// Key management (persisting the key identifier, regenerating on
/// ``AppAttestClientError/Code/invalidKey``) is intentionally left to the app.
@available(iOS 14.0, macOS 11.0, macCatalyst 14.0, tvOS 15.0, watchOS 9.0, visionOS 1.0, *)
public struct AppAttestService: Sendable {
    let backing: any AppAttestServiceBacking

    /// The wrapper around `DCAppAttestService.shared`.
    public static let shared = AppAttestService(backing: DCAppAttestService.shared)

    init(backing: any AppAttestServiceBacking) {
        self.backing = backing
    }

    /// A Boolean value that indicates whether this device supports App Attest.
    ///
    /// Returns `false` on simulators and on devices without the required
    /// hardware. When unsupported, every other call throws
    /// ``AppAttestClientError/Code/featureUnsupported``.
    public var isSupported: Bool {
        backing.isSupported
    }

    /// Creates a new App Attest key pair in the Secure Enclave.
    ///
    /// - Returns: The identifier of the new key. Persist it — you need it for
    ///   attestation and for every subsequent assertion.
    /// - Throws: ``AppAttestClientError``.
    public func generateKey() async throws(AppAttestClientError) -> AppAttestKeyID {
        do {
            return AppAttestKeyID(base64EncodedString: try await backing.generateKey())
        } catch {
            throw AppAttestClientError(wrapping: error)
        }
    }

    /// Asks Apple to attest the key, producing an attestation object for your server.
    ///
    /// - Parameters:
    ///   - keyID: The identifier returned by ``generateKey()``.
    ///   - clientDataHash: The SHA-256 hash of a one-time challenge your server issued.
    /// - Returns: The CBOR-encoded attestation object. Send it to your server
    ///   together with `keyID` (see `AttestationPayload`).
    /// - Throws: ``AppAttestClientError``. This call contacts Apple's servers, so
    ///   ``AppAttestClientError/Code/serverUnavailable`` is a retryable failure.
    public func attestKey(_ keyID: AppAttestKeyID, clientDataHash: Data) async throws(AppAttestClientError) -> Data {
        do {
            return try await backing.attestKey(keyID.base64EncodedString, clientDataHash: clientDataHash)
        } catch {
            throw AppAttestClientError(wrapping: error)
        }
    }

    /// Asks Apple to attest the key, hashing the server challenge for you.
    ///
    /// A convenience over ``attestKey(_:clientDataHash:)`` that computes
    /// `SHA256(challenge)` — the hash `AttestationVerifier` on the server
    /// recomputes from the same raw challenge.
    ///
    /// - Parameters:
    ///   - keyID: The identifier returned by ``generateKey()``.
    ///   - challenge: The raw one-time challenge your server issued.
    public func attestKey(_ keyID: AppAttestKeyID, challenge: Data) async throws(AppAttestClientError) -> Data {
        try await attestKey(keyID, clientDataHash: Data(SHA256.hash(data: challenge)))
    }

    /// Signs a request with the attested key, producing an assertion object.
    ///
    /// - Parameters:
    ///   - keyID: The identifier of a key your server has already verified an
    ///     attestation for.
    ///   - clientDataHash: The SHA-256 hash of the client data — typically your
    ///     request body with an embedded server challenge.
    /// - Returns: The CBOR-encoded assertion object. Send it to your server
    ///   together with the exact client data bytes (see `AssertionPayload`).
    /// - Throws: ``AppAttestClientError``.
    public func generateAssertion(
        _ keyID: AppAttestKeyID,
        clientDataHash: Data
    ) async throws(AppAttestClientError) -> Data {
        do {
            return try await backing.generateAssertion(keyID.base64EncodedString, clientDataHash: clientDataHash)
        } catch {
            throw AppAttestClientError(wrapping: error)
        }
    }

    /// Signs a request with the attested key, hashing the client data for you.
    ///
    /// A convenience over ``generateAssertion(_:clientDataHash:)`` that
    /// computes `SHA256(clientData)`. Send the exact same `clientData` bytes
    /// to your server — `AssertionVerifier` recomputes the hash from them.
    ///
    /// - Parameters:
    ///   - keyID: The identifier of a key your server has already verified an
    ///     attestation for.
    ///   - clientData: The client data — typically your request body with an
    ///     embedded server challenge.
    public func generateAssertion(
        _ keyID: AppAttestKeyID,
        clientData: Data
    ) async throws(AppAttestClientError) -> Data {
        try await generateAssertion(keyID, clientDataHash: Data(SHA256.hash(data: clientData)))
    }
}

/// Abstraction over `DCAppAttestService` used for unit-testing the wrapper.
protocol AppAttestServiceBacking: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

@available(iOS 14.0, macOS 11.0, macCatalyst 14.0, tvOS 15.0, watchOS 9.0, visionOS 1.0, *)
extension DCAppAttestService: AppAttestServiceBacking {}

// `DCAppAttestService` is a stateless Objective-C singleton; it is safe to use
// from any thread even though the SDK doesn't annotate it as Sendable.
extension DCAppAttestService: @retroactive @unchecked Sendable {}
#endif
