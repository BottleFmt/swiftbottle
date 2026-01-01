import Foundation

/// Errors that can occur during Bottle operations
public enum BottleError: Error, LocalizedError {
    /// No appropriate key available to decrypt the message
    case noAppropriateKey

    /// Signature verification failed
    case verifyFailed

    /// The requested key was not found
    case keyNotFound

    /// The provided key is not suitable for the requested operation
    case keyUnfit(String)

    /// Cannot encrypt without at least one valid recipient
    case encryptNoRecipient

    /// Invalid message format
    case invalidFormat(String)

    /// CBOR decoding failed
    case decodingFailed(String)

    /// CBOR encoding failed
    case encodingFailed(String)

    /// Invalid key format
    case invalidKey(String)

    /// Cryptographic operation failed
    case cryptoError(String)

    /// Group not found
    case groupNotFound

    /// Invalid bottle structure
    case invalidBottle(String)

    public var errorDescription: String? {
        switch self {
        case .noAppropriateKey:
            return "No appropriate key available to open bottle"
        case .verifyFailed:
            return "Signature verification failed"
        case .keyNotFound:
            return "The key was not found"
        case .keyUnfit(let reason):
            return "The provided key was not fit: \(reason)"
        case .encryptNoRecipient:
            return "Cannot encrypt a message without at least one valid recipient"
        case .invalidFormat(let reason):
            return "Invalid format: \(reason)"
        case .decodingFailed(let reason):
            return "Decoding failed: \(reason)"
        case .encodingFailed(let reason):
            return "Encoding failed: \(reason)"
        case .invalidKey(let reason):
            return "Invalid key: \(reason)"
        case .cryptoError(let reason):
            return "Cryptographic error: \(reason)"
        case .groupNotFound:
            return "The group was not found"
        case .invalidBottle(let reason):
            return "Invalid bottle: \(reason)"
        }
    }
}
