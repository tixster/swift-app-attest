import Crypto
import Foundation
import Testing
import X509
@testable import AppAttestServer

@Suite("AttestationVerifier")
struct AttestationVerifierTests {
    @Test func acceptsValidAttestation() async throws {
        let fixture = try AttestationFixture.make()
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        let result = try await verifier.verify(
            attestation: fixture.attestation,
            keyID: fixture.keyID,
            challenge: fixture.challenge
        )

        #expect(result.publicKey.x963Representation == fixture.attestedKey.publicKey.x963Representation)
        #expect(result.environment == .development)
        #expect(result.signCount == 0)
        #expect(result.receipt == fixture.options.receipt)
        #expect(result.validationCategory == .appStore)
        #expect(result.bundleVersion == "1.2.3")
        #expect(result.keyID == fixture.keyID)
        #expect(result.publicKeyX963Representation.count == 65)
        #expect(!result.publicKeyDERRepresentation.isEmpty)
    }

    @Test func acceptsProductionEnvironment() async throws {
        let fixture = try AttestationFixture.make { $0.environment = .production }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        let result = try await verifier.verify(
            attestation: fixture.attestation,
            keyID: fixture.keyID,
            challenge: fixture.challenge
        )
        #expect(result.environment == .production)
    }

    @Test func acceptsAttestationWithoutAuthenticatorExtensions() async throws {
        let fixture = try AttestationFixture.make { $0.includeAuthenticatorExtensions = false }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        let result = try await verifier.verify(
            attestation: fixture.attestation,
            keyID: fixture.keyID,
            challenge: fixture.challenge
        )
        #expect(result.validationCategory == nil)
        #expect(result.bundleVersion == nil)
    }

    @Test func rejectsWrongChallenge() async throws {
        let fixture = try AttestationFixture.make()
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.nonceMismatch) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: Data("some other challenge".utf8)
            )
        }
    }

    @Test func rejectsWrongCertificateNonce() async throws {
        let fixture = try AttestationFixture.make {
            $0.certificateNonceOverride = Data(repeating: 0xab, count: 32)
        }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.nonceMismatch) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsUntrustedChain() async throws {
        let fixture = try AttestationFixture.make()
        // Verify against the real Apple root instead of the test root.
        var configuration = fixture.configuration
        configuration.attestationTrustRoots = nil
        let verifier = AttestationVerifier(configuration: configuration)

        await #expect {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        } throws: { error in
            if case .certificateChainValidationFailed = error as? AppAttestVerificationError {
                return true
            }
            return false
        }
    }

    @Test func rejectsMismatchedKeyID() async throws {
        let fixture = try AttestationFixture.make()
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.keyIdentifierMismatch) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: AppAttestKeyID(rawBytes: Data(repeating: 0x11, count: 32)),
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsUndecodableKeyID() async throws {
        let fixture = try AttestationFixture.make()
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.invalidKeyIdentifier) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: AppAttestKeyID(base64EncodedString: "*** not base64 ***"),
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsWrongAppID() async throws {
        let fixture = try AttestationFixture.make()
        var configuration = fixture.configuration
        configuration.bundleIdentifier = "com.example.other"
        let verifier = AttestationVerifier(configuration: configuration)

        await #expect(throws: AppAttestVerificationError.appIDMismatch) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsNonZeroCounter() async throws {
        let fixture = try AttestationFixture.make { $0.counter = 7 }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.invalidCounter(7)) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsUnknownAAGUID() async throws {
        let aaguid = Data("not-an-aaguid-16".utf8)
        let fixture = try AttestationFixture.make { $0.aaguidOverride = aaguid }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.unknownAAGUID(aaguid)) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsDisallowedEnvironment() async throws {
        let fixture = try AttestationFixture.make { $0.environment = .development }
        var configuration = fixture.configuration
        configuration.environments = [.production]
        let verifier = AttestationVerifier(configuration: configuration)

        await #expect(throws: AppAttestVerificationError.environmentNotAllowed(.development)) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsMismatchedCredentialID() async throws {
        let fixture = try AttestationFixture.make {
            $0.credentialIDOverride = Data(repeating: 0x22, count: 32)
        }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.credentialIDMismatch) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsUnknownFormat() async throws {
        let fixture = try AttestationFixture.make { $0.format = "packed" }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestVerificationError.unsupportedAttestationFormat("packed")) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    @Test func rejectsGarbageAttestation() async throws {
        let fixture = try AttestationFixture.make()
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        await #expect {
            _ = try await verifier.verify(
                attestation: Data([0xff, 0x00, 0x01]),
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        } throws: { error in
            if case .malformedAttestation = error as? AppAttestVerificationError {
                return true
            }
            return false
        }
    }

    @Test func acceptsExpectedMacOSAccessControlPolicyWhenEnabled() async throws {
        let fixture = try AttestationFixture.make {
            $0.aclBlob = AppleCertificateExtensions.expectedAccessControlPolicy
        }
        var configuration = fixture.configuration
        configuration.validatesMacOSAccessControlPolicy = true
        let verifier = AttestationVerifier(configuration: configuration)

        _ = try await verifier.verify(
            attestation: fixture.attestation,
            keyID: fixture.keyID,
            challenge: fixture.challenge
        )
    }

    @Test func rejectsUnexpectedMacOSAccessControlPolicyWhenEnabled() async throws {
        let fixture = try AttestationFixture.make {
            $0.aclBlob = Data("weakened access policy".utf8)
        }
        var configuration = fixture.configuration
        configuration.validatesMacOSAccessControlPolicy = true
        let verifier = AttestationVerifier(configuration: configuration)

        await #expect(throws: AppAttestVerificationError.accessControlPolicyMismatch) {
            _ = try await verifier.verify(
                attestation: fixture.attestation,
                keyID: fixture.keyID,
                challenge: fixture.challenge
            )
        }
    }

    /// iOS 26 carries `aclBlob` with platform-specific contents — the default
    /// configuration must not reject such attestations.
    @Test func ignoresForeignAccessControlPolicyByDefault() async throws {
        let fixture = try AttestationFixture.make {
            $0.aclBlob = Data("iOS-style access policy".utf8)
        }
        let verifier = AttestationVerifier(configuration: fixture.configuration)

        _ = try await verifier.verify(
            attestation: fixture.attestation,
            keyID: fixture.keyID,
            challenge: fixture.challenge
        )
    }
}

@Suite("AppleTrustRoots")
struct AppleTrustRootsTests {
    @Test func rootsParse() {
        // Accessing the constants exercises the force-tried PEM parsing.
        #expect(String(describing: AppleTrustRoots.appAttestRootCA.subject).contains("Apple App Attestation Root CA"))
        #expect(String(describing: AppleTrustRoots.appleRootCAG3.subject).contains("Apple Root CA - G3"))
    }
}
