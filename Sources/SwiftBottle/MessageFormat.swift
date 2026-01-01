import Foundation

/// Message format enumeration for Bottle protocol
/// Indicates how the Message field should be interpreted
public enum MessageFormat: Int, Codable, Sendable {
    /// Raw, unencrypted data
    case clearText = 0

    /// Nested Bottle encoded using CBOR
    case cborBottle = 1

    /// AES-256-GCM encrypted CBOR Bottle
    case aes = 2

    /// Nested Bottle encoded using JSON
    case jsonBottle = 3
}

extension MessageFormat: CustomStringConvertible {
    public var description: String {
        switch self {
        case .clearText:
            return "ClearText"
        case .cborBottle:
            return "CborBottle"
        case .aes:
            return "AES"
        case .jsonBottle:
            return "JsonBottle"
        }
    }
}
