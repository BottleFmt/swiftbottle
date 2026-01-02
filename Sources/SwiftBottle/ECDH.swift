import Foundation
import CryptoKit
@preconcurrency import Security

// MARK: - ECDH Encryption

/// ECDH encryption format version
private let ecdhVersion: UInt8 = 0x00

/// Encrypt data using ECDH key agreement
/// Format: version(0x00) || keylen(varint) || ephemeral_pubkey || nonce || ciphertext
public func ecdhEncrypt(data: Data, remotePublicKey: PublicKeyType) throws -> Data {
    switch remotePublicKey {
    case .x25519(let key):
        return try ecdhEncryptX25519(data: data, remoteKey: key)
    case .ed25519(let key):
        // Convert Ed25519 public key to X25519 for encryption
        let x25519Key = try ed25519PublicToX25519(key)
        return try ecdhEncryptX25519(data: data, remoteKey: x25519Key)
    case .p256(let key):
        // Convert P256.Signing to P256.KeyAgreement
        let kaKey = try P256.KeyAgreement.PublicKey(rawRepresentation: key.rawRepresentation)
        return try ecdhEncryptP256(data: data, remoteKey: kaKey)
    case .p256KeyAgreement(let key):
        return try ecdhEncryptP256(data: data, remoteKey: key)
    case .rsa:
        throw BottleError.keyUnfit("RSA keys do not support ECDH encryption")
    }
}

/// Decrypt data using ECDH key agreement
public func ecdhDecrypt(data: Data, privateKey: PrivateKeyType) throws -> Data {
    guard data.count > 1 else {
        throw BottleError.decodingFailed("ECDH encrypted data too short")
    }

    let version = data[0]
    guard version == ecdhVersion else {
        throw BottleError.invalidFormat("Unknown ECDH version: \(version)")
    }

    switch privateKey {
    case .x25519(let key):
        return try ecdhDecryptX25519(data: data, privateKey: key)
    case .ed25519(let key):
        // Convert Ed25519 private key to X25519 for decryption
        let x25519Key = try ed25519PrivateToX25519(key)
        return try ecdhDecryptX25519(data: data, privateKey: x25519Key)
    case .p256(let key):
        // Convert P256.Signing to P256.KeyAgreement
        let kaKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: key.rawRepresentation)
        return try ecdhDecryptP256(data: data, privateKey: kaKey)
    case .p256KeyAgreement(let key):
        return try ecdhDecryptP256(data: data, privateKey: key)
    case .rsa:
        throw BottleError.keyUnfit("RSA keys do not support ECDH decryption")
    }
}

// MARK: - X25519 Implementation

private func ecdhEncryptX25519(data: Data, remoteKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
    // Generate ephemeral key pair
    let ephemeral = Curve25519.KeyAgreement.PrivateKey()

    // Perform ECDH
    let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(with: remoteKey)

    // Derive AES key using SHA-256
    let aesKey = sharedSecret.withUnsafeBytes { ptr in
        SHA256.hash(data: Data(ptr))
    }
    let symmetricKey = SymmetricKey(data: Data(aesKey))

    // Generate random nonce
    var nonceBytes = [UInt8](repeating: 0, count: 12)
    guard SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes) == errSecSuccess else {
        throw BottleError.cryptoError("Failed to generate random nonce")
    }
    let nonce = try AES.GCM.Nonce(data: Data(nonceBytes))

    // Encrypt with AES-GCM
    let sealed = try AES.GCM.seal(data, using: symmetricKey, nonce: nonce)

    // Get ephemeral public key in PKIX format
    let ephemeralPKIX = marshalX25519PublicKey(ephemeral.publicKey.rawRepresentation)

    // Build result: version || keylen || ephemeral_pubkey || nonce || ciphertext+tag
    var result = Data()
    result.append(ecdhVersion)
    result.append(contentsOf: encodeVarint(UInt64(ephemeralPKIX.count)))
    result.append(ephemeralPKIX)
    result.append(contentsOf: nonceBytes)
    result.append(sealed.ciphertext)
    result.append(sealed.tag)

    return result
}

private func ecdhDecryptX25519(data: Data, privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
    var offset = 1  // Skip version byte

    // Read ephemeral public key length
    let (keyLen, varintBytes) = try decodeVarint(data.subdata(in: offset..<data.count))
    offset += varintBytes

    // Read ephemeral public key
    guard offset + Int(keyLen) <= data.count else {
        throw BottleError.decodingFailed("ECDH data truncated")
    }
    let ephemeralPKIX = data.subdata(in: offset..<(offset + Int(keyLen)))
    offset += Int(keyLen)

    // Parse ephemeral public key
    guard let ephemeralKey = try? parsePKIXPublicKey(ephemeralPKIX),
          case .x25519(let ephemeral) = ephemeralKey else {
        throw BottleError.invalidKey("Invalid ephemeral X25519 key")
    }

    // Read nonce (12 bytes)
    guard offset + 12 <= data.count else {
        throw BottleError.decodingFailed("ECDH data truncated (nonce)")
    }
    let nonceBytes = data.subdata(in: offset..<(offset + 12))
    offset += 12

    // Rest is ciphertext + tag
    guard data.count > offset + 16 else {
        throw BottleError.decodingFailed("ECDH data truncated (ciphertext)")
    }
    let ciphertextAndTag = data.subdata(in: offset..<data.count)
    let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
    let tag = ciphertextAndTag.suffix(16)

    // Perform ECDH
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)

    // Derive AES key
    let aesKey = sharedSecret.withUnsafeBytes { ptr in
        SHA256.hash(data: Data(ptr))
    }
    let symmetricKey = SymmetricKey(data: Data(aesKey))

    // Decrypt
    let nonce = try AES.GCM.Nonce(data: nonceBytes)
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

    return plaintext
}

// MARK: - P-256 Implementation

private func ecdhEncryptP256(data: Data, remoteKey: P256.KeyAgreement.PublicKey) throws -> Data {
    // Generate ephemeral key pair
    let ephemeral = P256.KeyAgreement.PrivateKey()

    // Perform ECDH
    let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(with: remoteKey)

    // Derive AES key using SHA-256
    let aesKey = sharedSecret.withUnsafeBytes { ptr in
        SHA256.hash(data: Data(ptr))
    }
    let symmetricKey = SymmetricKey(data: Data(aesKey))

    // Generate random nonce
    var nonceBytes = [UInt8](repeating: 0, count: 12)
    guard SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes) == errSecSuccess else {
        throw BottleError.cryptoError("Failed to generate random nonce")
    }
    let nonce = try AES.GCM.Nonce(data: Data(nonceBytes))

    // Encrypt with AES-GCM
    let sealed = try AES.GCM.seal(data, using: symmetricKey, nonce: nonce)

    // Get ephemeral public key in PKIX format
    let ephemeralPKIX = try marshalPKIXPublicKey(.p256KeyAgreement(ephemeral.publicKey))

    // Build result
    var result = Data()
    result.append(ecdhVersion)
    result.append(contentsOf: encodeVarint(UInt64(ephemeralPKIX.count)))
    result.append(ephemeralPKIX)
    result.append(contentsOf: nonceBytes)
    result.append(sealed.ciphertext)
    result.append(sealed.tag)

    return result
}

private func ecdhDecryptP256(data: Data, privateKey: P256.KeyAgreement.PrivateKey) throws -> Data {
    var offset = 1  // Skip version byte

    // Read ephemeral public key length
    let (keyLen, varintBytes) = try decodeVarint(data.subdata(in: offset..<data.count))
    offset += varintBytes

    // Read ephemeral public key
    guard offset + Int(keyLen) <= data.count else {
        throw BottleError.decodingFailed("ECDH data truncated")
    }
    let ephemeralPKIX = data.subdata(in: offset..<(offset + Int(keyLen)))
    offset += Int(keyLen)

    // Parse ephemeral public key
    let parsedKey = try parsePKIXPublicKey(ephemeralPKIX)
    let ephemeral: P256.KeyAgreement.PublicKey
    switch parsedKey {
    case .p256(let key):
        ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: key.rawRepresentation)
    case .p256KeyAgreement(let key):
        ephemeral = key
    default:
        throw BottleError.invalidKey("Invalid ephemeral P-256 key")
    }

    // Read nonce
    guard offset + 12 <= data.count else {
        throw BottleError.decodingFailed("ECDH data truncated (nonce)")
    }
    let nonceBytes = data.subdata(in: offset..<(offset + 12))
    offset += 12

    // Rest is ciphertext + tag
    guard data.count > offset + 16 else {
        throw BottleError.decodingFailed("ECDH data truncated (ciphertext)")
    }
    let ciphertextAndTag = data.subdata(in: offset..<data.count)
    let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
    let tag = ciphertextAndTag.suffix(16)

    // Perform ECDH
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)

    // Derive AES key
    let aesKey = sharedSecret.withUnsafeBytes { ptr in
        SHA256.hash(data: Data(ptr))
    }
    let symmetricKey = SymmetricKey(data: Data(aesKey))

    // Decrypt
    let nonce = try AES.GCM.Nonce(data: nonceBytes)
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

    return plaintext
}

// MARK: - Ed25519 to X25519 Conversion

/// Prime field modulus for Curve25519
private let curve25519Prime: [UInt64] = [
    0xFFFFFFFFFFFFFFED,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF
]

/// Convert Ed25519 public key to X25519 public key
/// Uses birational map: u = (1 + y) / (1 - y) mod p
public func ed25519PublicToX25519(_ ed25519Key: Curve25519.Signing.PublicKey) throws -> Curve25519.KeyAgreement.PublicKey {
    let yBytes = Array(ed25519Key.rawRepresentation)

    // Ed25519 public key is the y-coordinate with sign bit in MSB
    // Extract y as a field element
    let y = bytesToFieldElement(yBytes)

    // Compute u = (1 + y) / (1 - y) mod p
    var oneMinusY = fieldSubtract(fieldOne(), y)
    let onePlusY = fieldAdd(fieldOne(), y)

    // Invert (1 - y) using Fermat's little theorem: a^(p-2) mod p
    oneMinusY = fieldInvert(oneMinusY)

    // u = (1 + y) * (1 - y)^(-1)
    let u = fieldMultiply(onePlusY, oneMinusY)

    // Convert back to bytes
    let uBytes = fieldElementToBytes(u)

    return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(uBytes))
}

/// Convert Ed25519 private key to X25519 private key
public func ed25519PrivateToX25519(_ ed25519Key: Curve25519.Signing.PrivateKey) throws -> Curve25519.KeyAgreement.PrivateKey {
    // The Ed25519 private key raw representation is the seed
    // X25519 private key is derived by hashing with SHA-512 and clamping
    let seed = ed25519Key.rawRepresentation

    // Hash seed with SHA-512
    var hash = Array(SHA512.hash(data: seed))

    // Clamp the first 32 bytes
    hash[0] &= 248     // Clear bottom 3 bits
    hash[31] &= 127    // Clear top bit
    hash[31] |= 64     // Set second-to-top bit

    // Use first 32 bytes as X25519 private key
    let x25519Bytes = Data(hash.prefix(32))

    return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519Bytes)
}

// MARK: - Field Arithmetic (mod p = 2^255 - 19)

private typealias FieldElement = [UInt64]  // 4 limbs of 64 bits each

private func fieldOne() -> FieldElement {
    return [1, 0, 0, 0]
}

private func fieldZero() -> FieldElement {
    return [0, 0, 0, 0]
}

private func bytesToFieldElement(_ bytes: [UInt8]) -> FieldElement {
    var result: FieldElement = [0, 0, 0, 0]

    for i in 0..<4 {
        var limb: UInt64 = 0
        for j in 0..<8 {
            let byteIdx = i * 8 + j
            if byteIdx < bytes.count {
                limb |= UInt64(bytes[byteIdx]) << (j * 8)
            }
        }
        result[i] = limb
    }

    // Clear top bit (sign bit in Ed25519)
    result[3] &= 0x7FFFFFFFFFFFFFFF

    return result
}

private func fieldElementToBytes(_ fe: FieldElement) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: 32)

    for i in 0..<4 {
        for j in 0..<8 {
            result[i * 8 + j] = UInt8((fe[i] >> (j * 8)) & 0xFF)
        }
    }

    return result
}

private func fieldAdd(_ a: FieldElement, _ b: FieldElement) -> FieldElement {
    var result: FieldElement = [0, 0, 0, 0]
    var carry: UInt64 = 0

    for i in 0..<4 {
        let sum = a[i].addingReportingOverflow(b[i])
        let sum2 = sum.partialValue.addingReportingOverflow(carry)
        result[i] = sum2.partialValue
        carry = (sum.overflow ? 1 : 0) + (sum2.overflow ? 1 : 0)
    }

    // Reduce mod p if necessary
    return fieldReduce(result)
}

private func fieldSubtract(_ a: FieldElement, _ b: FieldElement) -> FieldElement {
    // a - b mod p = a + (p - b) mod p
    var result: FieldElement = [0, 0, 0, 0]
    var borrow: UInt64 = 0

    for i in 0..<4 {
        let diff = a[i].subtractingReportingOverflow(b[i])
        let diff2 = diff.partialValue.subtractingReportingOverflow(borrow)
        result[i] = diff2.partialValue
        borrow = (diff.overflow ? 1 : 0) + (diff2.overflow ? 1 : 0)
    }

    // If we borrowed, add p back
    if borrow > 0 {
        var carry: UInt64 = 0
        for i in 0..<4 {
            let sum = result[i].addingReportingOverflow(curve25519Prime[i])
            let sum2 = sum.partialValue.addingReportingOverflow(carry)
            result[i] = sum2.partialValue
            carry = (sum.overflow ? 1 : 0) + (sum2.overflow ? 1 : 0)
        }
    }

    return result
}

private func fieldMultiply(_ a: FieldElement, _ b: FieldElement) -> FieldElement {
    // Schoolbook multiplication with reduction
    var temp = [UInt64](repeating: 0, count: 8)

    for i in 0..<4 {
        var carry: UInt64 = 0
        for j in 0..<4 {
            let (high, low) = a[i].multipliedFullWidth(by: b[j])
            let sum1 = temp[i + j].addingReportingOverflow(low)
            let sum2 = sum1.partialValue.addingReportingOverflow(carry)
            temp[i + j] = sum2.partialValue
            carry = high + (sum1.overflow ? 1 : 0) + (sum2.overflow ? 1 : 0)
        }
        temp[i + 4] = temp[i + 4] &+ carry
    }

    // Reduce mod p using the fact that 2^256 ≡ 38 (mod p)
    var result: FieldElement = [0, 0, 0, 0]
    var carry: UInt64 = 0

    // temp[0..3] + 38 * temp[4..7]
    for i in 0..<4 {
        let (high, low) = temp[i + 4].multipliedFullWidth(by: 38)
        let sum1 = temp[i].addingReportingOverflow(low)
        let sum2 = sum1.partialValue.addingReportingOverflow(carry)
        result[i] = sum2.partialValue
        carry = high + (sum1.overflow ? 1 : 0) + (sum2.overflow ? 1 : 0)
    }

    // Handle remaining carry
    while carry > 0 {
        let (high, low) = carry.multipliedFullWidth(by: 38)
        let sum = result[0].addingReportingOverflow(low)
        result[0] = sum.partialValue
        carry = high + (sum.overflow ? 1 : 0)

        if carry > 0 {
            for i in 1..<4 {
                let s = result[i].addingReportingOverflow(carry)
                result[i] = s.partialValue
                carry = s.overflow ? 1 : 0
                if carry == 0 { break }
            }
        }
    }

    return fieldReduce(result)
}

private func fieldReduce(_ a: FieldElement) -> FieldElement {
    var result = a

    // Reduce if >= p
    // Check if result >= p by comparing from high to low
    var needsReduction = false
    if result[3] > curve25519Prime[3] {
        needsReduction = true
    } else if result[3] == curve25519Prime[3] {
        if result[2] > curve25519Prime[2] {
            needsReduction = true
        } else if result[2] == curve25519Prime[2] {
            if result[1] > curve25519Prime[1] {
                needsReduction = true
            } else if result[1] == curve25519Prime[1] {
                if result[0] >= curve25519Prime[0] {
                    needsReduction = true
                }
            }
        }
    }

    if needsReduction {
        var borrow: UInt64 = 0
        for i in 0..<4 {
            let diff = result[i].subtractingReportingOverflow(curve25519Prime[i])
            let diff2 = diff.partialValue.subtractingReportingOverflow(borrow)
            result[i] = diff2.partialValue
            borrow = (diff.overflow ? 1 : 0) + (diff2.overflow ? 1 : 0)
        }
    }

    return result
}

private func fieldInvert(_ a: FieldElement) -> FieldElement {
    // a^(p-2) mod p using square-and-multiply
    // p - 2 = 2^255 - 21

    var result = fieldOne()
    var base = a

    // p - 2 in binary: 11111...11101011 (255 bits, with specific pattern)
    // Exponent: 2^255 - 19 - 2 = 2^255 - 21

    // We'll use a simpler approach: repeated squaring for all 255 bits
    // then adjusting for the specific pattern

    // First, compute a^(2^255-21) using Fermat's little theorem
    // This is a^(p-2) = a^(-1) mod p

    // p - 2 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    let exp: [UInt64] = [
        0xFFFFFFFFFFFFFFEB,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF
    ]

    for i in 0..<4 {
        for j in 0..<64 {
            if (exp[i] >> j) & 1 == 1 {
                result = fieldMultiply(result, base)
            }
            base = fieldMultiply(base, base)
        }
    }

    return result
}

// MARK: - X25519 PKIX Marshaling Helper

private func marshalX25519PublicKey(_ rawKey: Data) -> Data {
    // SubjectPublicKeyInfo for X25519
    let oid: [UInt8] = [0x06, 0x03, 0x2B, 0x65, 0x6E]  // OID 1.3.101.110
    let algorithm = Data([0x30, 0x05]) + Data(oid)
    let bitString = Data([0x03, UInt8(rawKey.count + 1), 0x00]) + rawKey

    let content = algorithm + bitString
    return Data([0x30, UInt8(content.count)]) + content
}
