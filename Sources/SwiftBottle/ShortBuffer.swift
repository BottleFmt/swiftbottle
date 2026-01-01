import Foundation
import CryptoKit
@preconcurrency import Security

// MARK: - Short Buffer Encryption (Key Wrapping)

/// Encrypt a short buffer (typically an AES key) for a recipient
/// Uses the appropriate algorithm based on key type:
/// - RSA: RSA-OAEP with SHA-256
/// - EC/X25519/Ed25519: ECDH + AES-GCM
public func encryptShortBuffer(data: Data, publicKey: PublicKeyType) throws -> Data {
    switch publicKey {
    case .rsa(let key):
        return try rsaEncrypt(data: data, publicKey: key)
    case .ed25519, .x25519, .p256, .p256KeyAgreement:
        return try ecdhEncrypt(data: data, remotePublicKey: publicKey)
    }
}

/// Decrypt a short buffer using the appropriate algorithm
public func decryptShortBuffer(data: Data, privateKey: PrivateKeyType) throws -> Data {
    switch privateKey {
    case .rsa(let key):
        return try rsaDecrypt(data: data, privateKey: key)
    case .ed25519, .x25519, .p256, .p256KeyAgreement:
        return try ecdhDecrypt(data: data, privateKey: privateKey)
    }
}

// MARK: - RSA-OAEP Encryption

/// Encrypt using RSA-OAEP with SHA-256
private func rsaEncrypt(data: Data, publicKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?

    guard let encrypted = SecKeyCreateEncryptedData(
        publicKey,
        .rsaEncryptionOAEPSHA256,
        data as CFData,
        &error
    ) as Data? else {
        throw BottleError.cryptoError("RSA encryption failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
    }

    return encrypted
}

/// Decrypt using RSA-OAEP with SHA-256
private func rsaDecrypt(data: Data, privateKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?

    guard let decrypted = SecKeyCreateDecryptedData(
        privateKey,
        .rsaEncryptionOAEPSHA256,
        data as CFData,
        &error
    ) as Data? else {
        throw BottleError.cryptoError("RSA decryption failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
    }

    return decrypted
}
