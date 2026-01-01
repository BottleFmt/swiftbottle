import Foundation
import CryptoKit
@preconcurrency import Security

/// Keychain stores private keys indexed by their public key
public class Keychain: @unchecked Sendable {
    /// Keys indexed by PKIX-encoded public key bytes
    private var keys: [Data: PrivateKeyType] = [:]

    /// Create an empty keychain
    public init() {}

    /// Create a keychain with the given keys
    public init(_ keys: PrivateKeyType...) {
        for key in keys {
            try? addKey(key)
        }
    }

    /// Add a private key to the keychain
    public func addKey(_ key: PrivateKeyType) throws {
        let publicKeyPKIX = try marshalPKIXPublicKey(key.publicKey)
        keys[publicKeyPKIX] = key
    }

    /// Add multiple keys
    public func addKeys(_ keys: PrivateKeyType...) throws {
        for key in keys {
            try addKey(key)
        }
    }

    /// Get a private key by its public key
    public func getKey(forPublic publicKey: PublicKeyType) -> PrivateKeyType? {
        guard let publicKeyPKIX = try? marshalPKIXPublicKey(publicKey) else {
            return nil
        }
        return keys[publicKeyPKIX]
    }

    /// Get a private key by PKIX-encoded public key bytes
    public func getKey(forPKIX pkix: Data) -> PrivateKeyType? {
        return keys[pkix]
    }

    /// Check if a key exists
    public func hasKey(forPublic publicKey: PublicKeyType) -> Bool {
        return getKey(forPublic: publicKey) != nil
    }

    /// Check if a key exists by PKIX bytes
    public func hasKey(forPKIX pkix: Data) -> Bool {
        return keys[pkix] != nil
    }

    /// Get all keys
    public var allKeys: [PrivateKeyType] {
        return Array(keys.values)
    }

    /// Get the first signer key (signing-capable)
    public func firstSigner() -> PrivateKeyType? {
        for key in keys.values {
            switch key {
            case .ed25519, .p256, .rsa:
                return key
            default:
                continue
            }
        }
        return nil
    }

    /// Iterate over all keys
    public func forEach(_ body: (PrivateKeyType) throws -> Void) rethrows {
        for key in keys.values {
            try body(key)
        }
    }
}
