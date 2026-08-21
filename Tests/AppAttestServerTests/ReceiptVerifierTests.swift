import Crypto
import Foundation
import Testing
import X509
@testable import AppAttestServer

@Suite("ReceiptVerifier")
struct ReceiptVerifierTests {
    @Test func acceptsValidReceipt() async throws {
        let fixture = try ReceiptFixture.make()
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        let receipt = try await verifier.verify(
            receipt: fixture.receipt,
            expectedPublicKey: fixture.attestedKey.publicKey
        )

        #expect(receipt.appID == "TEAM123456.com.example.app")
        #expect(receipt.receiptType == .receipt)
        #expect(receipt.riskMetric == 3)
        #expect(receipt.token == fixture.options.token)
        #expect(receipt.clientHash == fixture.options.clientHash)
        #expect(receipt.notBefore != nil)
        #expect(abs(receipt.creationTime.timeIntervalSince(fixture.options.creationTime)) < 1)
        #expect(try receipt.attestedCertificate() == fixture.attestedCertificate)
    }

    @Test func acceptsAttestReceiptWithoutRiskMetric() async throws {
        let fixture = try ReceiptFixture.make {
            $0.receiptType = "ATTEST"
            $0.riskMetric = nil
            $0.notBefore = nil
        }
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        let receipt = try await verifier.verify(receipt: fixture.receipt, maximumCreationAge: 300)
        #expect(receipt.receiptType == .attest)
        #expect(receipt.riskMetric == nil)
        #expect(receipt.notBefore == nil)
    }

    @Test func parsesStringRiskMetric() async throws {
        let fixture = try ReceiptFixture.make {
            $0.riskMetric = 12
            $0.riskMetricAsString = true
        }
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        let receipt = try await verifier.verify(receipt: fixture.receipt)
        #expect(receipt.riskMetric == 12)
    }

    /// Apple emits receipts in BER: indefinite lengths on the container
    /// spine and a chunked `eContent` OCTET STRING. Verification must accept
    /// them — the CMS layer only understands strict DER, so the verifier
    /// normalizes first.
    @Test func acceptsBEREncodedReceipt() async throws {
        let fixture = try ReceiptFixture.make()
        let mangled = try BERMangler.mangle(fixture.receipt)
        #expect(mangled != fixture.receipt)
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        let receipt = try await verifier.verify(
            receipt: mangled,
            expectedPublicKey: fixture.attestedKey.publicKey
        )

        #expect(receipt.appID == "TEAM123456.com.example.app")
        #expect(receipt.riskMetric == 3)
    }

    @Test func normalizerRoundTripsBERBackToDER() throws {
        let fixture = try ReceiptFixture.make()
        let mangled = try BERMangler.mangle(fixture.receipt)

        // DER in — the same DER out, byte for byte.
        #expect(try BERNormalizer.normalizeToDER(fixture.receipt) == fixture.receipt)
        // The BER variant normalizes back to exactly the original DER.
        #expect(try BERNormalizer.normalizeToDER(mangled) == fixture.receipt)
    }

    @Test func rejectsUntrustedSigner() async throws {
        let fixture = try ReceiptFixture.make()
        var configuration = fixture.configuration
        configuration.receiptTrustRoots = nil  // real Apple root
        let verifier = ReceiptVerifier(configuration: configuration)

        await #expect {
            _ = try await verifier.verify(receipt: fixture.receipt)
        } throws: { error in
            if case .invalidSignature = error as? AppAttestReceiptError {
                return true
            }
            return false
        }
    }

    @Test func rejectsTamperedPayload() async throws {
        let fixture = try ReceiptFixture.make()
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        var tampered = fixture.receipt
        // Flip a byte near the end of the payload region.
        tampered[tampered.count / 2] ^= 0xff

        await #expect {
            _ = try await verifier.verify(receipt: tampered)
        } throws: { _ in true }
    }

    @Test func rejectsWrongAppID() async throws {
        let fixture = try ReceiptFixture.make { $0.appID = "OTHER00000.com.example.other" }
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        await #expect(
            throws: AppAttestReceiptError.appIDMismatch(
                expected: "TEAM123456.com.example.app",
                received: "OTHER00000.com.example.other"
            )
        ) {
            _ = try await verifier.verify(receipt: fixture.receipt)
        }
    }

    @Test func rejectsStaleReceipt() async throws {
        let creation = Date().addingTimeInterval(-3600)
        let fixture = try ReceiptFixture.make { $0.creationTime = creation }
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        await #expect {
            _ = try await verifier.verify(receipt: fixture.receipt, maximumCreationAge: 300)
        } throws: { error in
            if case .receiptTooOld = error as? AppAttestReceiptError {
                return true
            }
            return false
        }
    }

    @Test func rejectsExpiredReceipt() async throws {
        let fixture = try ReceiptFixture.make()
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        await #expect {
            _ = try await verifier.verify(
                receipt: fixture.receipt,
                at: fixture.options.expirationTime.addingTimeInterval(60)
            )
        } throws: { error in
            if case .receiptExpired = error as? AppAttestReceiptError {
                return true
            }
            return false
        }
    }

    @Test func rejectsMismatchedPublicKey() async throws {
        let fixture = try ReceiptFixture.make()
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestReceiptError.publicKeyMismatch) {
            _ = try await verifier.verify(
                receipt: fixture.receipt,
                expectedPublicKey: P256.Signing.PrivateKey().publicKey
            )
        }
    }

    @Test func rejectsMissingRequiredField() async throws {
        let fixture = try ReceiptFixture.make { $0.omitFields = [2] }
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        await #expect(throws: AppAttestReceiptError.missingField(2)) {
            _ = try await verifier.verify(receipt: fixture.receipt)
        }
    }

    @Test func rejectsGarbage() async throws {
        let fixture = try ReceiptFixture.make()
        let verifier = ReceiptVerifier(configuration: fixture.configuration)

        await #expect {
            _ = try await verifier.verify(receipt: Data("not a receipt".utf8))
        } throws: { _ in true }
    }
}
