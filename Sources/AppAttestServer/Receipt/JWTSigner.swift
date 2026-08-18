import Crypto
import Foundation

/// Produces the ES256 JSON Web Tokens that authenticate fraud-assessment
/// requests.
///
/// The token format follows Apple's provider-authentication-token scheme
/// (the same one APNs uses): header `{"alg": "ES256", "kid": <key ID>}`,
/// payload `{"iss": <team ID>, "iat": <seconds since epoch>}`.
enum JWTSigner {
    /// Creates a signed token.
    static func token(credentials: AppStoreConnectCredentials, issuedAt: Date = Date()) throws -> String {
        let header = base64URLEncodedJSON([
            "alg": "ES256",
            "kid": credentials.keyIdentifier,
            "typ": "JWT",
        ])
        let payload = base64URLEncodedJSON([
            "iss": credentials.teamIdentifier,
            "iat": Int(issuedAt.timeIntervalSince1970),
        ])
        let signingInput = "\(header).\(payload)"
        let signature = try credentials.privateKey.signature(for: Data(signingInput.utf8))
        return "\(signingInput).\(base64URLEncode(signature.rawRepresentation))"
    }

    private static func base64URLEncodedJSON(_ object: [String: any Sendable]) -> String {
        // The values above are always JSON-encodable, so this cannot throw.
        // swift-format-ignore: NeverForceUnwrap
        let json = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return base64URLEncode(json)
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
