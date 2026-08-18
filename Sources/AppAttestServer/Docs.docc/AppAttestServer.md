# ``AppAttestServer``

Server-side verification of Apple App Attest attestations, assertions, and receipts.

## Overview

App Attest lets your server confirm that requests come from a legitimate,
unmodified instance of your app running on a genuine Apple device. This module
implements the server half of the protocol on macOS and Linux:

- ``AttestationVerifier`` validates the attestation object a client sends at
  enrollment and extracts the attested public key.
- ``AssertionVerifier`` validates the assertions a client attaches to
  sensitive requests afterwards.
- ``ReceiptVerifier`` and ``FraudAssessmentClient`` handle receipts and the
  risk-metric exchange with Apple's servers.

All verifiers are configured with a single ``AppAttestConfiguration`` carrying
your Team ID, bundle identifier, and allowed environments.

## Topics

### Essentials

- <doc:VerifyingAttestations>
- <doc:VerifyingAssertions>
- <doc:AssessingFraudRisk>
- ``AppAttestConfiguration``
- ``AppAttestChallenge``

### Attestations

- ``AttestationVerifier``
- ``VerifiedAttestation``
- ``AttestationObject``
- ``AuthenticatorData``
- ``AuthenticatorDataExtensions``
- ``AppAttestValidationCategory``

### Assertions

- ``AssertionVerifier``
- ``VerifiedAssertion``
- ``AssertionObject``

### Receipts and fraud assessment

- ``ReceiptVerifier``
- ``AppAttestReceipt``
- ``FraudAssessmentClient``
- ``AppStoreConnectCredentials``

### Transport

- ``AppAttestHTTPClient``
- ``AppAttestHTTPRequest``
- ``AppAttestHTTPResponse``
- ``URLSessionAppAttestHTTPClient``

### Trust roots

- ``AppleTrustRoots``

### Errors

- ``AppAttestVerificationError``
- ``AppAttestReceiptError``
- ``FraudAssessmentError``
