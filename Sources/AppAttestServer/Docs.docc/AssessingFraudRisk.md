# Assessing Fraud Risk

Exchange receipts with Apple to detect devices that attest suspiciously many keys.

## Overview

Every attestation statement carries a receipt. By sending it to Apple's
fraud-assessment endpoint you receive a refreshed receipt with a *risk
metric*: the approximate number of keys attested for your app on that device
over the past 30 days. An unexpectedly high number can indicate a compromised
device serving assertions to many copies of your app.

## Verifying receipts

Verify a receipt — including the one that accompanies an attestation — with
``ReceiptVerifier`` before trusting it:

```swift
let receiptVerifier = ReceiptVerifier(configuration: configuration)
let receipt = try await receiptVerifier.verify(
    receipt: attestationResult.receipt,
    expectedPublicKey: attestationResult.publicKey,
    maximumCreationAge: 300  // Apple recommends 5 minutes at enrollment
)
```

This checks the PKCS #7 signature up to Apple Root CA - G3, the App ID, the
attested public key, the creation time, and the expiration time, and returns
the decoded payload as an ``AppAttestReceipt``.

## Requesting the risk metric

``FraudAssessmentClient`` authenticates with an App Store Connect key (create
it with the DeviceCheck service enabled) and exchanges a stored receipt for a
refreshed one:

```swift
let client = FraudAssessmentClient(
    environment: .production,
    credentials: try AppStoreConnectCredentials(
        keyIdentifier: "ABC123DEFG",
        teamIdentifier: "A1B2C3D4E5",
        privateKeyPEM: p8FileContents
    )
)

let refreshedData = try await client.refreshReceipt(storedReceipt)
let refreshed = try await receiptVerifier.verify(
    receipt: refreshedData,
    expectedPublicKey: storedPublicKey
)
let riskMetric = refreshed.riskMetric
```

Store the refreshed receipt in place of the old one — it's the input for the
next exchange. Respect the receipt's schedule: refreshing before
``AppAttestReceipt/notBefore`` yields ``FraudAssessmentError/notModified``,
and receipts stop being exchangeable after
``AppAttestReceipt/expirationTime``, so refresh periodically.

Receipts are bound to their environment: a development receipt can only be
exchanged against the development endpoint, and vice versa.
