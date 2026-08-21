import Foundation
import AppAttestCore

/// Errors thrown while verifying attestation and assertion objects.
///
/// Each case corresponds to a specific step of Apple's validation procedure, so
/// a failure tells you exactly which check rejected the input.
public enum AppAttestVerificationError: Error, Sendable, Hashable {
    // MARK: Parsing

    /// The attestation object isn't valid CBOR or is missing required entries.
    case malformedAttestation(reason: String)

    /// The assertion object isn't valid CBOR or is missing required entries.
    case malformedAssertion(reason: String)

    /// The authenticator data inside the object couldn't be parsed.
    case malformedAuthenticatorData(reason: String)

    /// The attestation's `fmt` entry isn't `apple-appattest`.
    case unsupportedAttestationFormat(String)

    /// The supplied key identifier isn't valid Base64.
    case invalidKeyIdentifier

    // MARK: Attestation checks

    /// The attestation contains no certificate chain (`x5c`).
    case certificateChainMissing

    /// The certificate chain doesn't verify against the App Attest root CA.
    case certificateChainValidationFailed(reason: String)

    /// The credential certificate has no nonce extension (OID 1.2.840.113635.100.8.2).
    case nonceExtensionMissing

    /// The nonce in the credential certificate doesn't match
    /// `SHA256(authData || SHA256(challenge))`.
    case nonceMismatch

    /// The access-control policy blob (OID 1.2.840.113635.100.8.6) doesn't
    /// match the value Apple defines for macOS with SIP plus Full Security
    /// mode. Only thrown when the opt-in
    /// ``AppAttestConfiguration/validatesMacOSAccessControlPolicy`` check is
    /// enabled; iOS attestations carry the extension with different contents.
    case accessControlPolicyMismatch

    /// `SHA256(credential certificate public key)` doesn't equal the key identifier.
    case keyIdentifierMismatch

    /// The credential certificate's key isn't a P-256 key.
    case unsupportedPublicKey

    /// The authenticator data's RP ID hash doesn't equal `SHA256(appID)`.
    case appIDMismatch

    /// The attestation's counter isn't `0`.
    case invalidCounter(UInt32)

    /// The AAGUID isn't one of the App Attest environment markers.
    case unknownAAGUID(Data)

    /// The attestation was created in an environment the configuration doesn't allow.
    case environmentNotAllowed(AppAttestEnvironment)

    /// The authenticator data's `credentialId` doesn't equal the key identifier.
    case credentialIDMismatch

    // MARK: Assertion checks

    /// The assertion's signature isn't valid for
    /// `SHA256(authenticatorData || SHA256(clientData))` under the stored public key.
    case invalidSignature

    /// The assertion's counter isn't greater than the previous one.
    case counterNotIncreasing(previous: UInt32, received: UInt32)

    /// The challenge embedded in the client data doesn't match the expected challenge.
    case challengeMismatch

    /// The `challengeExtractor` closure threw while pulling the challenge out
    /// of the client data.
    case challengeExtractionFailed(reason: String)
}
