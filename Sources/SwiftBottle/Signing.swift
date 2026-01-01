import Foundation
import CryptoKit
@preconcurrency import Security

// MARK: - Signing

/// Sign data with a private key
/// Returns the signature bytes appropriate for the key type
public func sign(privateKey: PrivateKeyType, data: Data) throws -> Data {
    switch privateKey {
    case .ed25519(let key):
        return try signEd25519(key: key, data: data)
    case .p256(let key):
        return try signECDSA(key: key, data: data)
    case .rsa(let key):
        return try signRSA(key: key, data: data)
    case .x25519, .p256KeyAgreement:
        throw BottleError.keyUnfit("Key agreement keys cannot be used for signing")
    }
}

/// Sign data with Ed25519
private func signEd25519(key: Curve25519.Signing.PrivateKey, data: Data) throws -> Data {
    let signature = try key.signature(for: data)
    return signature
}

/// Sign data with ECDSA P-256
/// Returns ASN.1 DER encoded signature
private func signECDSA(key: P256.Signing.PrivateKey, data: Data) throws -> Data {
    let signature = try key.signature(for: data)
    return signature.derRepresentation
}

/// Sign data with RSA (PKCS#1 v1.5 with SHA-256)
private func signRSA(key: SecKey, data: Data) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        key,
        .rsaSignatureMessagePKCS1v15SHA256,
        data as CFData,
        &error
    ) as Data? else {
        throw BottleError.cryptoError("RSA signing failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
    }

    return signature
}

// MARK: - Verification

/// Verify a signature against data using a public key
public func verify(publicKey: PublicKeyType, data: Data, signature: Data) throws {
    switch publicKey {
    case .ed25519(let key):
        try verifyEd25519(key: key, data: data, signature: signature)
    case .p256(let key):
        try verifyECDSA(key: key, data: data, signature: signature)
    case .rsa(let key):
        try verifyRSA(key: key, data: data, signature: signature)
    case .x25519, .p256KeyAgreement:
        throw BottleError.keyUnfit("Key agreement keys cannot be used for verification")
    }
}

/// Verify Ed25519 signature
private func verifyEd25519(key: Curve25519.Signing.PublicKey, data: Data, signature: Data) throws {
    guard key.isValidSignature(signature, for: data) else {
        throw BottleError.verifyFailed
    }
}

/// Verify ECDSA P-256 signature (ASN.1 DER encoded)
private func verifyECDSA(key: P256.Signing.PublicKey, data: Data, signature: Data) throws {
    do {
        let ecdsaSig = try P256.Signing.ECDSASignature(derRepresentation: signature)
        guard key.isValidSignature(ecdsaSig, for: data) else {
            throw BottleError.verifyFailed
        }
    } catch {
        throw BottleError.verifyFailed
    }
}

/// Verify RSA signature (PKCS#1 v1.5 with SHA-256)
private func verifyRSA(key: SecKey, data: Data, signature: Data) throws {
    var error: Unmanaged<CFError>?
    let isValid = SecKeyVerifySignature(
        key,
        .rsaSignatureMessagePKCS1v15SHA256,
        data as CFData,
        signature as CFData,
        &error
    )

    guard isValid else {
        throw BottleError.verifyFailed
    }
}

// MARK: - MessageSignature Extension

extension MessageSignature {
    /// Verify this signature against the given message data
    public func verify(message: Data) throws {
        guard type == 0 else {
            throw BottleError.invalidFormat("Unknown signature type: \(type)")
        }

        let publicKey = try parsePKIXPublicKey(signer)
        try SwiftBottle.verify(publicKey: publicKey, data: message, signature: data)
    }
}

// MARK: - Bottle Signing Extension

extension Bottle {
    /// Sign the bottle's message with the given private key
    /// Adds a signature to the signatures array
    public mutating func sign(privateKey: PrivateKeyType) throws {
        let publicKeyData = try marshalPKIXPublicKey(privateKey.publicKey)
        let signatureData = try SwiftBottle.sign(privateKey: privateKey, data: message)

        let sig = MessageSignature(
            type: 0,
            signer: publicKeyData,
            data: signatureData
        )

        signatures.append(sig)
    }

    /// Verify all signatures on this bottle
    /// Throws if any signature is invalid
    public func verifySignatures() throws {
        for sig in signatures {
            try sig.verify(message: message)
        }
    }

    /// Check if the bottle is signed by the given public key
    public func isSignedBy(_ publicKey: PublicKeyType) -> Bool {
        guard let pkixData = try? marshalPKIXPublicKey(publicKey) else {
            return false
        }

        for sig in signatures {
            if sig.signer == pkixData {
                // Found matching signer, verify the signature
                if (try? sig.verify(message: message)) != nil {
                    return true
                }
            }
        }

        return false
    }
}
