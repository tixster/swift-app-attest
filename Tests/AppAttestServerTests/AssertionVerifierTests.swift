import Crypto
import Foundation
import Testing
@testable import AppAttestServer

@Suite("AssertionVerifier")
struct AssertionVerifierTests {
    let configuration = AppAttestConfiguration(
        teamIdentifier: "TEAM123456",
        bundleIdentifier: "com.example.app"
    )
    let key = P256.Signing.PrivateKey()

    var verifier: AssertionVerifier {
        AssertionVerifier(configuration: configuration)
    }

    @Test func acceptsValidAssertion() throws {
        let clientData = Data(#"{"action":"purchase","challenge":"c2VydmVyLWNoYWxsZW5nZQ=="}"#.utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) { $0.counter = 5 }

        let result = try verifier.verify(
            assertion: assertion,
            clientData: clientData,
            publicKey: key.publicKey,
            previousSignCount: 4
        )
        #expect(result.signCount == 5)
        #expect(result.validationCategory == nil)
    }

    /// Devices differ on whether the nonce is signed as a digest or as a
    /// message; both must verify.
    @Test func acceptsNonceSignedAsMessage() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) {
            $0.counter = 7
            $0.signsNonceAsMessage = true
        }

        let result = try verifier.verify(
            assertion: assertion,
            clientData: clientData,
            publicKey: key.publicKey,
            previousSignCount: 6
        )
        #expect(result.signCount == 7)
    }

    /// iOS 26 sets the `AT` flag in assertion authenticator data without
    /// appending a credential data section — a 37-byte payload must parse.
    @Test func acceptsIOS26AssertionWithSpuriousATFlag() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) {
            $0.counter = 2
            $0.spuriousAttestedCredentialDataFlag = true
        }

        let result = try verifier.verify(
            assertion: assertion,
            clientData: clientData,
            publicKey: key.publicKey,
            previousSignCount: 1
        )
        #expect(result.signCount == 2)
    }

    /// The same quirk combined with extensions: the trailing CBOR map must be
    /// read as extensions, not misparsed as credential data.
    @Test func acceptsIOS26AssertionWithSpuriousATFlagAndExtensions() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) {
            $0.counter = 3
            $0.spuriousAttestedCredentialDataFlag = true
            $0.includeExtensions = true
        }

        let result = try verifier.verify(
            assertion: assertion,
            clientData: clientData,
            publicKey: key.publicKey,
            previousSignCount: 2
        )
        #expect(result.validationCategory == .appStore)
        #expect(result.bundleVersion == "1.2.3")
    }

    @Test func acceptsAssertionWithExtensions() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) {
            $0.counter = 1
            $0.includeExtensions = true
        }

        let result = try verifier.verify(
            assertion: assertion,
            clientData: clientData,
            publicKey: key.publicKey,
            previousSignCount: 0
        )
        #expect(result.validationCategory == .appStore)
        #expect(result.bundleVersion == "1.2.3")
    }

    @Test func verifiesChallengeAsWholeClientData() throws {
        let challenge = Data("bare-challenge".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: challenge)

        _ = try verifier.verify(
            assertion: assertion,
            clientData: challenge,
            publicKey: key.publicKey,
            previousSignCount: 0,
            expectedChallenge: challenge
        )

        #expect(throws: AppAttestVerificationError.challengeMismatch) {
            _ = try verifier.verify(
                assertion: assertion,
                clientData: challenge,
                publicKey: key.publicKey,
                previousSignCount: 0,
                expectedChallenge: Data("different".utf8)
            )
        }
    }

    @Test func verifiesChallengeViaExtractor() throws {
        struct Request: Codable {
            var action: String
            var challenge: Data
        }
        let challenge = Data("embedded-challenge".utf8)
        let clientData = try JSONEncoder().encode(Request(action: "download", challenge: challenge))
        let assertion = try AssertionFixture.make(key: key, clientData: clientData)

        _ = try verifier.verify(
            assertion: assertion,
            clientData: clientData,
            publicKey: key.publicKey,
            previousSignCount: 0,
            expectedChallenge: challenge,
            challengeExtractor: { data in
                try JSONDecoder().decode(Request.self, from: data).challenge
            }
        )
    }

    @Test func rejectsInvalidSignature() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) {
            $0.corruptSignature = true
        }

        #expect(throws: AppAttestVerificationError.invalidSignature) {
            _ = try verifier.verify(
                assertion: assertion,
                clientData: clientData,
                publicKey: key.publicKey,
                previousSignCount: 0
            )
        }
    }

    @Test func rejectsSignatureFromAnotherKey() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: P256.Signing.PrivateKey(), clientData: clientData)

        #expect(throws: AppAttestVerificationError.invalidSignature) {
            _ = try verifier.verify(
                assertion: assertion,
                clientData: clientData,
                publicKey: key.publicKey,
                previousSignCount: 0
            )
        }
    }

    @Test func rejectsTamperedClientData() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData)

        #expect(throws: AppAttestVerificationError.invalidSignature) {
            _ = try verifier.verify(
                assertion: assertion,
                clientData: Data("tampered payload".utf8),
                publicKey: key.publicKey,
                previousSignCount: 0
            )
        }
    }

    @Test func rejectsStaleCounter() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) { $0.counter = 3 }

        #expect(throws: AppAttestVerificationError.counterNotIncreasing(previous: 3, received: 3)) {
            _ = try verifier.verify(
                assertion: assertion,
                clientData: clientData,
                publicKey: key.publicKey,
                previousSignCount: 3
            )
        }
    }

    @Test func rejectsWrongAppID() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData) {
            $0.appIdentifier = "TEAM123456.com.example.other"
        }

        #expect(throws: AppAttestVerificationError.appIDMismatch) {
            _ = try verifier.verify(
                assertion: assertion,
                clientData: clientData,
                publicKey: key.publicKey,
                previousSignCount: 0
            )
        }
    }

    @Test func acceptsX963PublicKey() throws {
        let clientData = Data("payload".utf8)
        let assertion = try AssertionFixture.make(key: key, clientData: clientData)

        let result = try verifier.verify(
            assertion: assertion,
            clientData: clientData,
            publicKeyX963Representation: key.publicKey.x963Representation,
            previousSignCount: 0
        )
        #expect(result.signCount == 1)

        #expect(throws: AppAttestVerificationError.unsupportedPublicKey) {
            _ = try verifier.verify(
                assertion: assertion,
                clientData: clientData,
                publicKeyX963Representation: Data([0x04, 0x01]),
                previousSignCount: 0
            )
        }
    }

    @Test func rejectsGarbageAssertion() throws {
        #expect {
            _ = try verifier.verify(
                assertion: Data([0x00, 0x01]),
                clientData: Data(),
                publicKey: key.publicKey,
                previousSignCount: 0
            )
        } throws: { error in
            if case .malformedAssertion = error as? AppAttestVerificationError {
                return true
            }
            return false
        }
    }
}
