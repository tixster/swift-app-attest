import Foundation
import Testing
@testable import AppAttestServer

@Suite("AppAttestChallenge")
struct ChallengeTests {
    @Test func defaultsTo32Bytes() {
        #expect(AppAttestChallenge.generate().count == 32)
    }

    @Test func respectsRequestedLength() {
        #expect(AppAttestChallenge.generate(byteCount: 16).count == 16)
        #expect(AppAttestChallenge.generate(byteCount: 64).count == 64)
    }

    @Test func producesUniqueValues() {
        let challenges = (0..<100).map { _ in AppAttestChallenge.generate() }
        #expect(Set(challenges).count == challenges.count)
    }
}
