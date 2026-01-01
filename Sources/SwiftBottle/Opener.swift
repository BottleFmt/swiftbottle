import Foundation
import CryptoKit
import SwiftCBOR
@preconcurrency import Security

/// Result of opening a bottle
public struct OpenResult: Sendable {
    /// Number of decryption layers traversed
    public var decryptionCount: Int

    /// All signatures encountered during opening
    public var signatures: [MessageSignature]

    /// All bottles encountered (outermost to innermost)
    public var bottles: [Bottle]

    public init(
        decryptionCount: Int = 0,
        signatures: [MessageSignature] = [],
        bottles: [Bottle] = []
    ) {
        self.decryptionCount = decryptionCount
        self.signatures = signatures
        self.bottles = bottles
    }

    /// Get the first (outermost) bottle
    public var first: Bottle? {
        return bottles.first
    }

    /// Get the last (innermost) bottle
    public var last: Bottle? {
        return bottles.last
    }

    /// Check if the message was signed by the given public key
    public func signedBy(_ publicKey: PublicKeyType) -> Bool {
        guard let pkix = try? marshalPKIXPublicKey(publicKey) else {
            return false
        }
        return signatures.contains { $0.signer == pkix }
    }

    /// Check if the message was signed by a key matching the PKIX data
    public func signedBy(pkix: Data) -> Bool {
        return signatures.contains { $0.signer == pkix }
    }
}

/// Opener handles decryption and verification of bottles
public class Opener: @unchecked Sendable {
    /// Keys available for decryption
    private let keychain: Keychain

    /// Create an opener with the given private keys
    public init(_ keys: PrivateKeyType...) {
        self.keychain = Keychain()
        for key in keys {
            try? keychain.addKey(key)
        }
    }

    /// Create an opener with a keychain
    public init(keychain: Keychain) {
        self.keychain = keychain
    }

    /// Create an empty opener (for signature verification only)
    public static let empty = Opener()

    /// Open a bottle, decrypting and verifying as needed
    /// Returns the final plaintext data and information about the opening process
    public func open(_ bottle: Bottle) throws -> (Data, OpenResult) {
        var result = OpenResult()
        var currentBottle = bottle

        while true {
            // Add bottle to result
            result.bottles.append(currentBottle)

            // Verify and collect signatures
            for sig in currentBottle.signatures {
                do {
                    try sig.verify(message: currentBottle.message)
                    result.signatures.append(sig)
                } catch {
                    throw BottleError.verifyFailed
                }
            }

            // Process based on format
            switch currentBottle.format {
            case .clearText:
                // We've reached the plaintext
                return (currentBottle.message, result)

            case .cborBottle:
                // Unwrap nested CBOR bottle
                currentBottle = try Bottle.fromCBOR(currentBottle.message)

            case .jsonBottle:
                // Unwrap nested JSON bottle
                currentBottle = try Bottle.fromJSON(currentBottle.message)

            case .aes:
                // Decrypt
                guard let decrypted = try decryptBottle(currentBottle) else {
                    throw BottleError.noAppropriateKey
                }
                currentBottle = decrypted
                result.decryptionCount += 1
            }
        }
    }

    /// Open a CBOR-encoded bottle
    public func openCBOR(_ data: Data) throws -> (Data, OpenResult) {
        let bottle = try Bottle.fromCBOR(data)
        return try open(bottle)
    }

    /// Open a JSON-encoded bottle
    public func openJSON(_ data: Data) throws -> (Data, OpenResult) {
        let bottle = try Bottle.fromJSON(data)
        return try open(bottle)
    }

    /// Open a bottle and unmarshal the content
    public func unmarshal<T: Decodable>(_ bottle: Bottle, as type: T.Type) throws -> (T, OpenResult) {
        let (data, result) = try open(bottle)

        // Check content type from innermost bottle
        let contentType = result.last?.header["ct"] as? String ?? "cbor"

        let decoded: T
        if contentType == "json" {
            decoded = try JSONDecoder().decode(T.self, from: data)
        } else {
            // For CBOR, we need to use a CBOR decoder
            // For now, convert via JSON as intermediate
            guard let cbor = try? CBOR.decode(Array(data)) else {
                throw BottleError.decodingFailed("Invalid CBOR content")
            }
            let jsonData = try JSONSerialization.data(withJSONObject: cborToAny(cbor))
            decoded = try JSONDecoder().decode(T.self, from: jsonData)
        }

        return (decoded, result)
    }

    /// Try to decrypt an encrypted bottle using available keys
    private func decryptBottle(_ bottle: Bottle) throws -> Bottle? {
        guard bottle.format == .aes else {
            return nil
        }

        // Try each recipient
        for recipient in bottle.recipients {
            // Check if we have the matching private key
            if let privateKey = keychain.getKey(forPKIX: recipient.recipient) {
                return try bottle.decrypt(privateKey: privateKey)
            }
        }

        // Try brute force decryption with all keys
        for key in keychain.allKeys {
            for recipient in bottle.recipients {
                do {
                    // Try decrypting this recipient's key
                    let _ = try decryptShortBuffer(data: recipient.data, privateKey: key)
                    // If we get here, decryption worked
                    return try bottle.decrypt(privateKey: key)
                } catch {
                    // Try next
                    continue
                }
            }
        }

        return nil
    }
}

/// Global empty opener for signature verification only
public let emptyOpener = Opener.empty

/// Create an opener with the given keys
public func newOpener(_ keys: PrivateKeyType...) -> Opener {
    let keychain = Keychain()
    for key in keys {
        try? keychain.addKey(key)
    }
    return Opener(keychain: keychain)
}
