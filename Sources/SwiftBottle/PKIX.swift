import Foundation
import CryptoKit
@preconcurrency import Security

// MARK: - Key Type Protocol

/// Protocol for public keys that can be serialized to PKIX format
public protocol PKIXPublicKey {
    /// Get the raw key bytes (without PKIX wrapper)
    var rawRepresentation: Data { get }
}

/// Protocol for private keys
public protocol PKIXPrivateKey {
    /// Get the raw key bytes
    var rawRepresentation: Data { get }
}

// MARK: - Key Type Enum

/// Represents different public key types
public enum PublicKeyType: Sendable {
    case ed25519(Curve25519.Signing.PublicKey)
    case x25519(Curve25519.KeyAgreement.PublicKey)
    case p256(P256.Signing.PublicKey)
    case p256KeyAgreement(P256.KeyAgreement.PublicKey)
    case rsa(SecKey)

    /// Get raw bytes representation
    public var rawRepresentation: Data {
        switch self {
        case .ed25519(let key):
            return key.rawRepresentation
        case .x25519(let key):
            return key.rawRepresentation
        case .p256(let key):
            return key.rawRepresentation
        case .p256KeyAgreement(let key):
            return key.rawRepresentation
        case .rsa(let key):
            // For RSA, return the PKIX-encoded key
            var error: Unmanaged<CFError>?
            guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
                return Data()
            }
            return data
        }
    }
}

/// Represents different private key types
public enum PrivateKeyType: Sendable {
    case ed25519(Curve25519.Signing.PrivateKey)
    case x25519(Curve25519.KeyAgreement.PrivateKey)
    case p256(P256.Signing.PrivateKey)
    case p256KeyAgreement(P256.KeyAgreement.PrivateKey)
    case rsa(SecKey)

    /// Get the corresponding public key
    public var publicKey: PublicKeyType {
        switch self {
        case .ed25519(let key):
            return .ed25519(key.publicKey)
        case .x25519(let key):
            return .x25519(key.publicKey)
        case .p256(let key):
            return .p256(key.publicKey)
        case .p256KeyAgreement(let key):
            return .p256KeyAgreement(key.publicKey)
        case .rsa(let key):
            guard let pubKey = SecKeyCopyPublicKey(key) else {
                fatalError("Failed to get public key from RSA private key")
            }
            return .rsa(pubKey)
        }
    }
}

// MARK: - OIDs

/// ASN.1 OIDs for key types
private enum OID {
    // Ed25519: 1.3.101.112
    static let ed25519: [UInt8] = [0x06, 0x03, 0x2B, 0x65, 0x70]

    // X25519: 1.3.101.110
    static let x25519: [UInt8] = [0x06, 0x03, 0x2B, 0x65, 0x6E]

    // EC Public Key: 1.2.840.10045.2.1
    static let ecPublicKey: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]

    // P-256 (secp256r1): 1.2.840.10045.3.1.7
    static let p256: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

    // RSA: 1.2.840.113549.1.1.1
    static let rsaEncryption: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
}

// MARK: - PKIX Parsing

/// Parse a PKIX-encoded (SubjectPublicKeyInfo) public key
public func parsePKIXPublicKey(_ der: Data) throws -> PublicKeyType {
    let bytes = Array(der)

    // Parse SEQUENCE
    guard bytes.count > 2 else {
        throw BottleError.invalidKey("Key data too short")
    }

    guard bytes[0] == 0x30 else {
        throw BottleError.invalidKey("Expected SEQUENCE tag")
    }

    // Check for Ed25519 OID
    if containsOID(bytes, OID.ed25519) {
        return try parseEd25519PublicKey(bytes)
    }

    // Check for X25519 OID
    if containsOID(bytes, OID.x25519) {
        return try parseX25519PublicKey(bytes)
    }

    // Check for EC (P-256) OID
    if containsOID(bytes, OID.ecPublicKey) && containsOID(bytes, OID.p256) {
        return try parseP256PublicKey(der)
    }

    // Check for RSA OID
    if containsOID(bytes, OID.rsaEncryption) {
        return try parseRSAPublicKey(der)
    }

    throw BottleError.invalidKey("Unknown key type")
}

/// Parse a PKIX-encoded private key (PKCS#8 or SEC1)
public func parsePKIXPrivateKey(_ der: Data) throws -> PrivateKeyType {
    let bytes = Array(der)

    guard bytes.count > 2 else {
        throw BottleError.invalidKey("Key data too short")
    }

    // Check for Ed25519 OID (PKCS#8 format)
    if containsOID(bytes, OID.ed25519) {
        return try parseEd25519PrivateKey(bytes)
    }

    // Check for X25519 OID
    if containsOID(bytes, OID.x25519) {
        return try parseX25519PrivateKey(bytes)
    }

    // Check for RSA
    if containsOID(bytes, OID.rsaEncryption) {
        return try parseRSAPrivateKey(der)
    }

    // For EC keys, try SEC1 format first (more common for raw EC keys)
    // SEC1 format starts with SEQUENCE and version INTEGER 1
    if bytes[0] == 0x30 && bytes.count > 4 {
        // Check if this looks like SEC1 format: SEQUENCE { INTEGER(1), OCTET STRING, ... }
        // Skip SEQUENCE tag and length
        var offset = 1
        if bytes[offset] >= 0x80 {
            offset += 1 + Int(bytes[offset] & 0x7F)
        } else {
            offset += 1
        }

        // Check for INTEGER tag
        if offset < bytes.count && bytes[offset] == 0x02 {
            // Looks like SEC1 format, try parsing
            if let key = try? parseECPrivateKeySEC1(der) {
                return key
            }
        }
    }

    // Try PKCS#8 EC key format
    if containsOID(bytes, OID.ecPublicKey) || containsOID(bytes, OID.p256) {
        return try parseP256PrivateKey(der)
    }

    throw BottleError.invalidKey("Unknown private key type")
}

// MARK: - Ed25519 Parsing

private func parseEd25519PublicKey(_ bytes: [UInt8]) throws -> PublicKeyType {
    // Find the BIT STRING containing the key
    // SEQUENCE { SEQUENCE { OID }, BIT STRING }
    guard let keyData = extractBitString(bytes) else {
        throw BottleError.invalidKey("Failed to extract Ed25519 public key")
    }

    guard keyData.count == 32 else {
        throw BottleError.invalidKey("Ed25519 public key must be 32 bytes, got \(keyData.count)")
    }

    let key = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
    return .ed25519(key)
}

private func parseEd25519PrivateKey(_ bytes: [UInt8]) throws -> PrivateKeyType {
    // PKCS#8 format: SEQUENCE { INTEGER version, SEQUENCE { OID }, OCTET STRING { OCTET STRING key } }
    guard let keyData = extractOctetStringFromPKCS8(bytes) else {
        throw BottleError.invalidKey("Failed to extract Ed25519 private key")
    }

    guard keyData.count == 32 else {
        throw BottleError.invalidKey("Ed25519 private key must be 32 bytes, got \(keyData.count)")
    }

    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
    return .ed25519(key)
}

// MARK: - X25519 Parsing

private func parseX25519PublicKey(_ bytes: [UInt8]) throws -> PublicKeyType {
    guard let keyData = extractBitString(bytes) else {
        throw BottleError.invalidKey("Failed to extract X25519 public key")
    }

    guard keyData.count == 32 else {
        throw BottleError.invalidKey("X25519 public key must be 32 bytes, got \(keyData.count)")
    }

    let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData)
    return .x25519(key)
}

private func parseX25519PrivateKey(_ bytes: [UInt8]) throws -> PrivateKeyType {
    guard let keyData = extractOctetStringFromPKCS8(bytes) else {
        throw BottleError.invalidKey("Failed to extract X25519 private key")
    }

    guard keyData.count == 32 else {
        throw BottleError.invalidKey("X25519 private key must be 32 bytes, got \(keyData.count)")
    }

    let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyData)
    return .x25519(key)
}

// MARK: - P-256 Parsing

private func parseP256PublicKey(_ der: Data) throws -> PublicKeyType {
    // Use CryptoKit's x963 representation parsing
    // First extract the key bytes from PKIX format
    let bytes = Array(der)

    guard let keyData = extractBitString(bytes) else {
        throw BottleError.invalidKey("Failed to extract P-256 public key")
    }

    // P-256 public key is 65 bytes (04 || x || y) for uncompressed
    let key = try P256.Signing.PublicKey(x963Representation: keyData)
    return .p256(key)
}

private func parseP256PrivateKey(_ der: Data) throws -> PrivateKeyType {
    // Try using Security framework for parsing
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    ]

    var error: Unmanaged<CFError>?
    if let secKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) {
        // Extract raw key and create CryptoKit key
        guard let rawData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw BottleError.invalidKey("Failed to extract P-256 private key data")
        }
        let key = try P256.Signing.PrivateKey(x963Representation: rawData)
        return .p256(key)
    }

    throw BottleError.invalidKey("Failed to parse P-256 private key")
}

private func parseECPrivateKeySEC1(_ der: Data) throws -> PrivateKeyType {
    // SEC1 format: SEQUENCE { INTEGER version, OCTET STRING privateKey, [0] params, [1] publicKey }
    // We need to extract the private key bytes and use CryptoKit directly

    let bytes = Array(der)

    // Parse outer SEQUENCE
    guard bytes.count > 4 && bytes[0] == 0x30 else {
        throw BottleError.invalidKey("Invalid SEC1 EC private key structure")
    }

    var offset = 1

    // Parse SEQUENCE length
    let (_, seqLenBytes) = parseASN1Length(Array(bytes.suffix(from: offset)))
    offset += seqLenBytes

    // Parse version INTEGER (should be 1)
    guard bytes[offset] == 0x02 else {
        throw BottleError.invalidKey("Expected INTEGER version")
    }
    offset += 1
    let versionLen = Int(bytes[offset])
    offset += 1 + versionLen

    // Parse privateKey OCTET STRING
    guard bytes[offset] == 0x04 else {
        throw BottleError.invalidKey("Expected OCTET STRING for private key")
    }
    offset += 1
    let privKeyLen = Int(bytes[offset])
    offset += 1

    guard offset + privKeyLen <= bytes.count else {
        throw BottleError.invalidKey("Private key data truncated")
    }

    let privateKeyBytes = Data(bytes[offset..<(offset + privKeyLen)])
    offset += privKeyLen

    // For P-256, private key should be 32 bytes
    guard privateKeyBytes.count == 32 else {
        throw BottleError.invalidKey("P-256 private key must be 32 bytes, got \(privateKeyBytes.count)")
    }

    // Create CryptoKit P-256 private key from raw bytes
    let key = try P256.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
    return .p256(key)
}

private func parseASN1Length(_ bytes: [UInt8]) -> (Int, Int) {
    guard !bytes.isEmpty else { return (0, 0) }

    if bytes[0] < 128 {
        return (Int(bytes[0]), 1)
    } else {
        let numBytes = Int(bytes[0] & 0x7F)
        guard bytes.count > numBytes else { return (0, 0) }

        var length = 0
        for i in 1...numBytes {
            length = (length << 8) | Int(bytes[i])
        }
        return (length, numBytes + 1)
    }
}

// MARK: - RSA Parsing

private func parseRSAPublicKey(_ der: Data) throws -> PublicKeyType {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
    ]

    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
        throw BottleError.invalidKey("Failed to parse RSA public key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
    }

    return .rsa(secKey)
}

private func parseRSAPrivateKey(_ der: Data) throws -> PrivateKeyType {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    ]

    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
        throw BottleError.invalidKey("Failed to parse RSA private key")
    }

    return .rsa(secKey)
}

// MARK: - PKIX Marshaling

/// Marshal a public key to PKIX (SubjectPublicKeyInfo) DER format
public func marshalPKIXPublicKey(_ key: PublicKeyType) throws -> Data {
    switch key {
    case .ed25519(let k):
        return marshalEd25519PublicKey(k.rawRepresentation)
    case .x25519(let k):
        return marshalX25519PublicKey(k.rawRepresentation)
    case .p256(let k):
        return try marshalP256PublicKey(k)
    case .p256KeyAgreement(let k):
        return try marshalP256KeyAgreementPublicKey(k)
    case .rsa(let k):
        return try marshalRSAPublicKey(k)
    }
}

private func marshalEd25519PublicKey(_ rawKey: Data) -> Data {
    // SubjectPublicKeyInfo for Ed25519:
    // SEQUENCE {
    //   SEQUENCE { OID 1.3.101.112 }
    //   BIT STRING (key)
    // }

    let algorithm = Data([0x30, 0x05]) + Data(OID.ed25519)  // SEQUENCE { OID }
    let bitString = Data([0x03, UInt8(rawKey.count + 1), 0x00]) + rawKey  // BIT STRING

    let content = algorithm + bitString
    return Data([0x30, UInt8(content.count)]) + content
}

private func marshalX25519PublicKey(_ rawKey: Data) -> Data {
    let algorithm = Data([0x30, 0x05]) + Data(OID.x25519)
    let bitString = Data([0x03, UInt8(rawKey.count + 1), 0x00]) + rawKey

    let content = algorithm + bitString
    return Data([0x30, UInt8(content.count)]) + content
}

private func marshalP256PublicKey(_ key: P256.Signing.PublicKey) throws -> Data {
    // SubjectPublicKeyInfo for P-256:
    // SEQUENCE {
    //   SEQUENCE { OID ecPublicKey, OID p256 }
    //   BIT STRING (04 || x || y)
    // }

    let x963 = key.x963Representation

    // Algorithm identifier: SEQUENCE { ecPublicKey OID, p256 OID }
    let algContent = Data(OID.ecPublicKey) + Data(OID.p256)
    let algorithm = Data([0x30, UInt8(algContent.count)]) + algContent

    // BIT STRING with 0 unused bits
    let bitString = Data([0x03, UInt8(x963.count + 1), 0x00]) + x963

    let content = algorithm + bitString
    return Data([0x30, UInt8(content.count)]) + content
}

private func marshalP256KeyAgreementPublicKey(_ key: P256.KeyAgreement.PublicKey) throws -> Data {
    let x963 = key.x963Representation

    let algContent = Data(OID.ecPublicKey) + Data(OID.p256)
    let algorithm = Data([0x30, UInt8(algContent.count)]) + algContent

    let bitString = Data([0x03, UInt8(x963.count + 1), 0x00]) + x963

    let content = algorithm + bitString
    return Data([0x30, UInt8(content.count)]) + content
}

private func marshalRSAPublicKey(_ key: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
        throw BottleError.invalidKey("Failed to export RSA public key")
    }

    // SecKey exports RSA keys in PKCS#1 format, we need to wrap in SubjectPublicKeyInfo
    // SEQUENCE {
    //   SEQUENCE { OID rsaEncryption, NULL }
    //   BIT STRING (PKCS#1 key)
    // }

    let nullParam = Data([0x05, 0x00])  // NULL
    let algContent = Data(OID.rsaEncryption) + nullParam
    let algorithm = Data([0x30, UInt8(algContent.count)]) + algContent

    // BIT STRING
    let bitString = wrapBitString(data)

    let content = algorithm + bitString
    return wrapSequence(content)
}

// MARK: - ASN.1 Helpers

private func containsOID(_ bytes: [UInt8], _ oid: [UInt8]) -> Bool {
    guard oid.count <= bytes.count else { return false }

    for i in 0...(bytes.count - oid.count) {
        var match = true
        for j in 0..<oid.count {
            if bytes[i + j] != oid[j] {
                match = false
                break
            }
        }
        if match { return true }
    }
    return false
}

private func extractBitString(_ bytes: [UInt8]) -> Data? {
    // Find BIT STRING tag (0x03)
    for i in 0..<bytes.count {
        if bytes[i] == 0x03 && i + 1 < bytes.count {
            let length = Int(bytes[i + 1])
            if i + 2 + length <= bytes.count {
                // Skip the "unused bits" byte
                let start = i + 3
                let end = i + 2 + length
                if start < end && end <= bytes.count {
                    return Data(bytes[start..<end])
                }
            }
        }
    }
    return nil
}

private func extractOctetStringFromPKCS8(_ bytes: [UInt8]) -> Data? {
    // PKCS#8 format has nested OCTET STRINGs for some key types
    // We look for the last OCTET STRING which contains the actual key

    var lastOctetString: Data?

    for i in 0..<bytes.count {
        if bytes[i] == 0x04 && i + 1 < bytes.count {
            let length = Int(bytes[i + 1])
            if i + 2 + length <= bytes.count {
                let data = Data(bytes[(i + 2)..<(i + 2 + length)])

                // For Ed25519/X25519, the key is wrapped in another OCTET STRING
                if data.count > 2 && data[0] == 0x04 {
                    let innerLength = Int(data[1])
                    if innerLength + 2 <= data.count {
                        lastOctetString = data.subdata(in: 2..<(2 + innerLength))
                    }
                } else if data.count == 32 {
                    lastOctetString = data
                }
            }
        }
    }

    return lastOctetString
}

private func wrapBitString(_ data: Data) -> Data {
    var result = Data()
    result.append(0x03)  // BIT STRING tag

    let contentLength = data.count + 1  // +1 for unused bits byte
    result.append(contentsOf: encodeLength(contentLength))
    result.append(0x00)  // unused bits
    result.append(data)

    return result
}

private func wrapSequence(_ data: Data) -> Data {
    var result = Data()
    result.append(0x30)  // SEQUENCE tag
    result.append(contentsOf: encodeLength(data.count))
    result.append(data)
    return result
}

private func encodeLength(_ length: Int) -> [UInt8] {
    if length < 128 {
        return [UInt8(length)]
    } else if length < 256 {
        return [0x81, UInt8(length)]
    } else if length < 65536 {
        return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
    } else {
        // For longer lengths
        return [0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
    }
}

// MARK: - Key Comparison

extension PublicKeyType: Equatable {
    public static func == (lhs: PublicKeyType, rhs: PublicKeyType) -> Bool {
        switch (lhs, rhs) {
        case (.ed25519(let a), .ed25519(let b)):
            return a.rawRepresentation == b.rawRepresentation
        case (.x25519(let a), .x25519(let b)):
            return a.rawRepresentation == b.rawRepresentation
        case (.p256(let a), .p256(let b)):
            return a.rawRepresentation == b.rawRepresentation
        case (.p256KeyAgreement(let a), .p256KeyAgreement(let b)):
            return a.rawRepresentation == b.rawRepresentation
        case (.rsa(let a), .rsa(let b)):
            // Compare RSA keys by their external representation
            var errorA: Unmanaged<CFError>?
            var errorB: Unmanaged<CFError>?
            guard let dataA = SecKeyCopyExternalRepresentation(a, &errorA) as Data?,
                  let dataB = SecKeyCopyExternalRepresentation(b, &errorB) as Data? else {
                return false
            }
            return dataA == dataB
        default:
            return false
        }
    }
}

// MARK: - PKIX Data Comparison

/// Compare a public key type with PKIX-encoded data
public func publicKeyMatchesPKIX(_ key: PublicKeyType, _ pkixData: Data) -> Bool {
    guard let parsedKey = try? parsePKIXPublicKey(pkixData) else {
        return false
    }
    return key == parsedKey
}
