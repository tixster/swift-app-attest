import Foundation

/// Server-side generation of App Attest challenges.
///
/// A challenge is an unpredictable, single-use value your server hands to the
/// client before an attestation or assertion. The library only generates the
/// bytes — storing the challenge (with a short TTL, bound to the user or
/// session) and invalidating it after the first verification attempt is your
/// application's job:
///
/// ```swift
/// // GET /app-attest/challenge
/// let challenge = AppAttestChallenge.generate()
/// try await cache.set("attest:\(userID)", challenge, ttl: .seconds(300))
/// return ChallengeResponse(challenge: challenge)
///
/// // POST /app-attest/enroll — consume before verifying, success or not
/// guard let challenge = try await cache.getAndDelete("attest:\(userID)") else {
///     throw Abort(.badRequest)
/// }
/// let result = try await attestationVerifier.verify(
///     attestation: payload.attestation,
///     keyID: payload.keyID,
///     challenge: challenge
/// )
/// ```
public enum AppAttestChallenge {
    /// Generates a challenge from the system's cryptographically secure
    /// random number generator.
    ///
    /// - Parameter byteCount: The challenge length. Defaults to 32 bytes;
    ///   must be positive.
    public static func generate(byteCount: Int = 32) -> Data {
        precondition(byteCount > 0, "a challenge must contain at least one byte")
        var rng = SystemRandomNumberGenerator()
        return Data((0..<byteCount).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }
}
