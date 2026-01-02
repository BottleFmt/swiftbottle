import XCTest
import CryptoKit
@testable import SwiftBottle

/// Interoperability tests using pre-generated test data from Go implementation
final class InteropTests: XCTestCase {

    // MARK: - Signed Cleartext Tests

    func testAliceSignedCleartext() throws {
        let alice = try TestKeys.getAlice()

        let (data, result) = try emptyOpener.openCBOR(TestVectors.aliceSignedCleartext)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Hello from Alice!")
        XCTAssertTrue(result.signedBy(alice.publicKey))
        XCTAssertEqual(result.decryptionCount, 0)
    }

    func testChloeSignedCleartext() throws {
        let chloe = try TestKeys.getChloe()

        let (data, result) = try emptyOpener.openCBOR(TestVectors.chloeSignedCleartext)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Hello from Chloe!")
        XCTAssertTrue(result.signedBy(chloe.publicKey))
        XCTAssertEqual(result.decryptionCount, 0)
    }

    // MARK: - Encrypted Tests

    func testAliceToBobEncrypted() throws {
        let alice = try TestKeys.getAlice()
        let bob = try TestKeys.getBob()

        let opener = newOpener(bob)
        let (data, result) = try opener.openCBOR(TestVectors.aliceToBobEncrypted)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Secret message from Alice to Bob")
        XCTAssertTrue(result.signedBy(alice.publicKey))
        XCTAssertEqual(result.decryptionCount, 1)

        // Should fail without Bob's key
        XCTAssertThrowsError(try emptyOpener.openCBOR(TestVectors.aliceToBobEncrypted)) { error in
            XCTAssertTrue(error is BottleError)
        }
    }

    func testChloeToDanielEncrypted() throws {
        let chloe = try TestKeys.getChloe()
        let daniel = try TestKeys.getDaniel()

        let opener = newOpener(daniel)
        let (data, result) = try opener.openCBOR(TestVectors.chloeToDanielEncrypted)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Secret message from Chloe to Daniel")
        XCTAssertTrue(result.signedBy(chloe.publicKey))
        XCTAssertEqual(result.decryptionCount, 1)
    }

    func testAliceToBobAndDaniel() throws {
        let alice = try TestKeys.getAlice()
        let bob = try TestKeys.getBob()
        let daniel = try TestKeys.getDaniel()

        // Open with Bob's key
        let openerBob = newOpener(bob)
        let (data1, result1) = try openerBob.openCBOR(TestVectors.aliceToBobAndDaniel)

        XCTAssertEqual(String(data: data1, encoding: .utf8), "Secret for Bob and Daniel")
        XCTAssertTrue(result1.signedBy(alice.publicKey))

        // Open with Daniel's key
        let openerDaniel = newOpener(daniel)
        let (data2, result2) = try openerDaniel.openCBOR(TestVectors.aliceToBobAndDaniel)

        XCTAssertEqual(String(data: data2, encoding: .utf8), "Secret for Bob and Daniel")
        XCTAssertTrue(result2.signedBy(alice.publicKey))
    }

    func testAnonymousToBob() throws {
        let bob = try TestKeys.getBob()

        let opener = newOpener(bob)
        let (data, result) = try opener.openCBOR(TestVectors.anonymousToBob)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Anonymous secret to Bob")
        XCTAssertEqual(result.signatures.count, 0)
        XCTAssertEqual(result.decryptionCount, 1)
    }

    // MARK: - Multi-Signature Tests

    func testAliceAndChloeSigned() throws {
        let alice = try TestKeys.getAlice()
        let chloe = try TestKeys.getChloe()

        let (data, result) = try emptyOpener.openCBOR(TestVectors.aliceAndChloeSigned)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Signed by both Alice and Chloe")
        XCTAssertTrue(result.signedBy(alice.publicKey))
        XCTAssertTrue(result.signedBy(chloe.publicKey))
        XCTAssertEqual(result.signatures.count, 2)
    }

    // MARK: - Nested Encryption Tests

    func testNestedBobThenDaniel() throws {
        let alice = try TestKeys.getAlice()
        let bob = try TestKeys.getBob()
        let daniel = try TestKeys.getDaniel()

        // Need both keys to decrypt nested bottle
        let keychain = Keychain()
        try keychain.addKey(bob)
        try keychain.addKey(daniel)
        let opener = Opener(keychain: keychain)

        let (data, result) = try opener.openCBOR(TestVectors.nestedBobThenDaniel)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Doubly encrypted message")
        XCTAssertTrue(result.signedBy(alice.publicKey))
        XCTAssertEqual(result.decryptionCount, 2)

        // Should fail with only Daniel's key (outer layer needs Bob)
        let openerDanielOnly = newOpener(daniel)
        XCTAssertThrowsError(try openerDanielOnly.openCBOR(TestVectors.nestedBobThenDaniel))
    }

    // MARK: - IDCard Tests

    func testAliceIDCard() throws {
        let alice = try TestKeys.getAlice()

        let idcard = try IDCard.load(TestVectors.aliceIDCard)

        XCTAssertEqual(idcard.meta["name"], "Alice")
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "sign"))
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "decrypt"))
    }

    func testBobIDCard() throws {
        let bob = try TestKeys.getBob()

        let idcard = try IDCard.load(TestVectors.bobIDCard)

        XCTAssertEqual(idcard.meta["name"], "Bob")
        XCTAssertNoThrow(try idcard.testKeyPurpose(bob.publicKey, "sign"))
        XCTAssertNoThrow(try idcard.testKeyPurpose(bob.publicKey, "decrypt"))
    }

    func testChloeIDCard() throws {
        let chloe = try TestKeys.getChloe()

        let idcard = try IDCard.load(TestVectors.chloeIDCard)

        XCTAssertEqual(idcard.meta["name"], "Chloe")
        XCTAssertNoThrow(try idcard.testKeyPurpose(chloe.publicKey, "sign"))
        XCTAssertNoThrow(try idcard.testKeyPurpose(chloe.publicKey, "decrypt"))
    }

    func testDanielIDCard() throws {
        let daniel = try TestKeys.getDaniel()

        let idcard = try IDCard.load(TestVectors.danielIDCard)

        XCTAssertEqual(idcard.meta["name"], "Daniel")
        XCTAssertNoThrow(try idcard.testKeyPurpose(daniel.publicKey, "sign"))
        XCTAssertNoThrow(try idcard.testKeyPurpose(daniel.publicKey, "decrypt"))
    }

    // MARK: - CBOR Edge Case Tests

    func testEmptyMessage() throws {
        let alice = try TestKeys.getAlice()

        let (data, result) = try emptyOpener.openCBOR(TestVectors.emptyMessageCleartext)

        XCTAssertEqual(data.count, 0)
        XCTAssertTrue(result.signedBy(alice.publicKey))
    }

    func testUnsignedCleartext() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.unsignedCleartext)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Unsigned message")
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborNullPayload() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborNullPayload)

        // CBOR null is encoded as 0xf6 (single byte)
        XCTAssertEqual(data, Data([0xf6]))
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborEmptyArrayPayload() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborEmptyArrayPayload)

        // CBOR empty array is encoded as 0x80
        XCTAssertEqual(data, Data([0x80]))
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborEmptyMapPayload() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborEmptyMapPayload)

        // CBOR empty map is encoded as 0xa0
        XCTAssertEqual(data, Data([0xa0]))
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborEmptyStringPayload() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborEmptyStringPayload)

        // CBOR empty text string is encoded as 0x60
        XCTAssertEqual(data, Data([0x60]))
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testSignedEmptyHeader() throws {
        let alice = try TestKeys.getAlice()

        let (data, result) = try emptyOpener.openCBOR(TestVectors.signedEmptyHeader)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Message with empty header")
        XCTAssertTrue(result.signedBy(alice.publicKey))
    }

    func testSingleRecipientEncrypted() throws {
        let alice = try TestKeys.getAlice()
        let bob = try TestKeys.getBob()

        let opener = newOpener(bob)
        let (data, result) = try opener.openCBOR(TestVectors.singleRecipientEncrypted)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Single recipient test")
        XCTAssertTrue(result.signedBy(alice.publicKey))
        XCTAssertEqual(result.decryptionCount, 1)
    }

    func testEd25519SignedEmptyRecipients() throws {
        let chloe = try TestKeys.getChloe()

        let (data, result) = try emptyOpener.openCBOR(TestVectors.ed25519SignedEmptyRecipients)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Ed25519 signed, no recipients")
        XCTAssertTrue(result.signedBy(chloe.publicKey))
        XCTAssertEqual(result.decryptionCount, 0)
    }

    func testCborNestedPayload() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborNestedPayload)

        // Verify it's valid CBOR and can be parsed
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testHeaderWithVariousTypes() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.headerWithVariousTypes)

        XCTAssertEqual(String(data: data, encoding: .utf8), "Test message")
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborIntegerBoundaries() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborIntegerBoundaries)

        // Verify we got CBOR data back
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborBinary24Bytes() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborBinary24Bytes)

        // The payload contains a 24-byte binary "ABCDEFGHIJKLMNOPQRSTUVWX"
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborBinary256Bytes() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborBinary256Bytes)

        // The payload contains a 256-byte binary
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborArray24Elements() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborArray24Elements)

        // The payload is an array of 24 integers (0-23)
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testCborIntegerKeyMap() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborIntegerKeyMap)

        // The payload is a map with integer keys
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testSignedBinaryContent() throws {
        let alice = try TestKeys.getAlice()

        let (data, result) = try emptyOpener.openCBOR(TestVectors.signedBinaryContent)

        // Expect bytes 0x00-0x1f (32 bytes)
        XCTAssertEqual(data.count, 32)
        for i in 0..<32 {
            XCTAssertEqual(data[i], UInt8(i))
        }
        XCTAssertTrue(result.signedBy(alice.publicKey))
    }

    func testCborNegativeIntegers() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.cborNegativeIntegers)

        // The payload contains negative integers
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testLargeHeaderKey() throws {
        let (data, result) = try emptyOpener.openCBOR(TestVectors.largeHeaderKey)

        // CBOR null payload (0xf6)
        XCTAssertEqual(data, Data([0xf6]))
        XCTAssertEqual(result.signatures.count, 0)
    }

    // MARK: - IDCard Edge Case Tests

    func testIDCardMinimal() throws {
        let alice = try TestKeys.getAlice()

        let idcard = try IDCard.load(TestVectors.idcardMinimal)

        // Verify it has no or empty Meta
        XCTAssertTrue(idcard.meta.isEmpty)

        // Verify SubKeys exist
        XCTAssertGreaterThanOrEqual(idcard.subKeys.count, 1)

        // Verify key purpose
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "sign"))
    }

    func testIDCardEmptyMeta() throws {
        let idcard = try IDCard.load(TestVectors.idcardEmptyMeta)

        // Meta should be empty
        XCTAssertTrue(idcard.meta.isEmpty)
    }

    func testIDCardMultipleKeys() throws {
        let alice = try TestKeys.getAlice()
        let bob = try TestKeys.getBob()

        let idcard = try IDCard.load(TestVectors.idcardMultipleKeys)

        // Verify we have 2 SubKeys
        XCTAssertEqual(idcard.subKeys.count, 2)

        // Verify Alice's key has sign purpose
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "sign"))

        // Verify Bob's key has decrypt purpose
        XCTAssertNoThrow(try idcard.testKeyPurpose(bob.publicKey, "decrypt"))

        // Verify Meta
        XCTAssertEqual(idcard.meta["name"], "Alice")
    }

    func testIDCardEd25519Minimal() throws {
        let chloe = try TestKeys.getChloe()

        let idcard = try IDCard.load(TestVectors.idcardEd25519Minimal)

        // Verify key purpose
        XCTAssertNoThrow(try idcard.testKeyPurpose(chloe.publicKey, "sign"))
    }

    func testIDCardWithExpiry() throws {
        let idcard = try IDCard.load(TestVectors.idcardWithExpiry)

        // Verify SubKey has expiration
        XCTAssertEqual(idcard.subKeys.count, 1)
        XCTAssertNotNil(idcard.subKeys[0].expires)
    }

    func testIDCardMultiplePurposes() throws {
        let alice = try TestKeys.getAlice()

        let idcard = try IDCard.load(TestVectors.idcardMultiplePurposes)

        // Verify key has both purposes
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "sign"))
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "decrypt"))
    }
}

/// Basic bottle functionality tests
final class BottleTests: XCTestCase {

    func testCreateAndOpenCleartext() throws {
        let message = "Hello, World!".data(using: .utf8)!
        let bottle = newBottle(message)

        let cbor = try bottle.toCBOR()
        let (data, result) = try emptyOpener.openCBOR(cbor)

        XCTAssertEqual(data, message)
        XCTAssertEqual(result.decryptionCount, 0)
        XCTAssertEqual(result.signatures.count, 0)
    }

    func testSignAndVerify() throws {
        let alice = try TestKeys.getAlice()
        let message = "Signed message".data(using: .utf8)!

        var bottle = newBottle(message)
        try bottle.sign(privateKey: alice)

        let cbor = try bottle.toCBOR()
        let (data, result) = try emptyOpener.openCBOR(cbor)

        XCTAssertEqual(data, message)
        XCTAssertTrue(result.signedBy(alice.publicKey))
    }

    func testEncryptAndDecrypt() throws {
        let alice = try TestKeys.getAlice()
        let bob = try TestKeys.getBob()
        let message = "Secret message".data(using: .utf8)!

        var bottle = newBottle(message)
        try bottle.encrypt(bob.publicKey)

        let cbor = try bottle.toCBOR()

        // Should decrypt with Bob's key
        let opener = newOpener(bob)
        let (data, result) = try opener.openCBOR(cbor)

        XCTAssertEqual(data, message)
        XCTAssertEqual(result.decryptionCount, 1)

        // Should fail without Bob's key
        XCTAssertThrowsError(try emptyOpener.openCBOR(cbor))
    }

    func testSignThenEncrypt() throws {
        let alice = try TestKeys.getAlice()
        let bob = try TestKeys.getBob()
        let message = "Signed and encrypted".data(using: .utf8)!

        var bottle = newBottle(message)
        try bottle.sign(privateKey: alice)
        try bottle.bottleUp()
        try bottle.encrypt(bob.publicKey)

        let cbor = try bottle.toCBOR()

        let opener = newOpener(bob)
        let (data, result) = try opener.openCBOR(cbor)

        XCTAssertEqual(data, message)
        XCTAssertTrue(result.signedBy(alice.publicKey))
        XCTAssertEqual(result.decryptionCount, 1)
    }

    func testMultiRecipient() throws {
        let bob = try TestKeys.getBob()
        let daniel = try TestKeys.getDaniel()
        let message = "For both Bob and Daniel".data(using: .utf8)!

        var bottle = newBottle(message)
        try bottle.encrypt(recipients: [bob.publicKey, daniel.publicKey])

        let cbor = try bottle.toCBOR()

        // Both should be able to decrypt
        let openerBob = newOpener(bob)
        let (data1, _) = try openerBob.openCBOR(cbor)
        XCTAssertEqual(data1, message)

        let openerDaniel = newOpener(daniel)
        let (data2, _) = try openerDaniel.openCBOR(cbor)
        XCTAssertEqual(data2, message)
    }

    func testBottleUp() throws {
        let message = "Nested message".data(using: .utf8)!

        var bottle = newBottle(message)
        bottle.header["test"] = "value"

        try bottle.bottleUp()

        XCTAssertEqual(bottle.format, .cborBottle)
        XCTAssertTrue(bottle.header.isEmpty)

        // Get child
        let child = try bottle.child()
        XCTAssertEqual(child.message, message)
        XCTAssertEqual(child.header["test"] as? String, "value")
    }

    func testJSONEncoding() throws {
        let message = "JSON test".data(using: .utf8)!
        var bottle = newBottle(message)
        bottle.header["key"] = "value"

        let json = try bottle.toJSON()
        let restored = try Bottle.fromJSON(json)

        XCTAssertEqual(restored.message, message)
        XCTAssertEqual(restored.format, .clearText)
    }
}

/// PKIX key serialization tests
final class PKIXTests: XCTestCase {

    func testEd25519RoundTrip() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let pkix = try marshalPKIXPublicKey(.ed25519(publicKey))
        let parsed = try parsePKIXPublicKey(pkix)

        guard case .ed25519(let restored) = parsed else {
            XCTFail("Expected Ed25519 key")
            return
        }

        XCTAssertEqual(restored.rawRepresentation, publicKey.rawRepresentation)
    }

    func testX25519RoundTrip() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        let pkix = try marshalPKIXPublicKey(.x25519(publicKey))
        let parsed = try parsePKIXPublicKey(pkix)

        guard case .x25519(let restored) = parsed else {
            XCTFail("Expected X25519 key")
            return
        }

        XCTAssertEqual(restored.rawRepresentation, publicKey.rawRepresentation)
    }

    func testP256RoundTrip() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let pkix = try marshalPKIXPublicKey(.p256(publicKey))
        let parsed = try parsePKIXPublicKey(pkix)

        guard case .p256(let restored) = parsed else {
            XCTFail("Expected P-256 key")
            return
        }

        XCTAssertEqual(restored.rawRepresentation, publicKey.rawRepresentation)
    }

    func testParseTestKeys() throws {
        // Test that we can parse all test keys
        let _ = try TestKeys.getAlice()
        let _ = try TestKeys.getBob()
        let _ = try TestKeys.getChloe()
        let _ = try TestKeys.getDaniel()
    }
}

/// Signing tests
final class SigningTests: XCTestCase {

    func testEd25519Signing() throws {
        let chloe = try TestKeys.getChloe()
        let message = "Test message".data(using: .utf8)!

        let signature = try sign(privateKey: chloe, data: message)
        XCTAssertNoThrow(try verify(publicKey: chloe.publicKey, data: message, signature: signature))

        // Tampered message should fail
        let tampered = "Tampered message".data(using: .utf8)!
        XCTAssertThrowsError(try verify(publicKey: chloe.publicKey, data: tampered, signature: signature))
    }

    func testECDSASigning() throws {
        let alice = try TestKeys.getAlice()
        let message = "Test message".data(using: .utf8)!

        let signature = try sign(privateKey: alice, data: message)
        XCTAssertNoThrow(try verify(publicKey: alice.publicKey, data: message, signature: signature))

        // Tampered message should fail
        let tampered = "Tampered message".data(using: .utf8)!
        XCTAssertThrowsError(try verify(publicKey: alice.publicKey, data: tampered, signature: signature))
    }
}

/// IDCard tests
final class IDCardTests: XCTestCase {

    func testCreateAndSign() throws {
        let alice = try TestKeys.getAlice()

        var idcard = try IDCard(publicKey: alice.publicKey)
        idcard.meta["name"] = "Test Alice"

        let signedData = try idcard.sign(privateKey: alice)

        // Load and verify
        let loaded = try IDCard.load(signedData)
        XCTAssertEqual(loaded.meta["name"], "Test Alice")
    }

    func testKeyPurposes() throws {
        let alice = try TestKeys.getAlice()

        var idcard = try IDCard(publicKey: alice.publicKey)

        // Default purposes should be sign and decrypt
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "sign"))
        XCTAssertNoThrow(try idcard.testKeyPurpose(alice.publicKey, "decrypt"))

        // Non-existent purpose should throw
        XCTAssertThrowsError(try idcard.testKeyPurpose(alice.publicKey, "nonexistent"))
    }
}
