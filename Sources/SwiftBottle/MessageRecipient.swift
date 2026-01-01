import Foundation
import SwiftCBOR

/// A recipient entry in an encrypted Bottle
/// Contains the recipient's public key and the encrypted key material
public struct MessageRecipient: Sendable {
    /// Recipient type (0 = PKIX-encoded keys, the only type currently defined)
    public var type: Int

    /// Recipient's public key in PKIX DER format
    public var recipient: Data

    /// Encrypted key material (AES key encrypted for this recipient)
    public var data: Data

    public init(type: Int = 0, recipient: Data, data: Data) {
        self.type = type
        self.recipient = recipient
        self.data = data
    }
}

// MARK: - CBOR Encoding

extension MessageRecipient {
    /// Encode to CBOR as an array [type, recipient, data]
    public func toCBOR() -> CBOR {
        return .array([
            .unsignedInt(UInt64(type)),
            .byteString(Array(recipient)),
            .byteString(Array(data))
        ])
    }

    /// Decode from CBOR array
    public static func fromCBOR(_ cbor: CBOR) throws -> MessageRecipient {
        guard case .array(let arr) = cbor, arr.count == 3 else {
            throw BottleError.decodingFailed("MessageRecipient must be a 3-element array")
        }

        guard case .unsignedInt(let typeVal) = arr[0] else {
            throw BottleError.decodingFailed("MessageRecipient type must be an integer")
        }

        guard case .byteString(let recipientBytes) = arr[1] else {
            throw BottleError.decodingFailed("MessageRecipient recipient must be a byte string")
        }

        guard case .byteString(let dataBytes) = arr[2] else {
            throw BottleError.decodingFailed("MessageRecipient data must be a byte string")
        }

        return MessageRecipient(
            type: Int(typeVal),
            recipient: Data(recipientBytes),
            data: Data(dataBytes)
        )
    }
}

// MARK: - JSON Encoding

extension MessageRecipient {
    /// JSON keys
    private enum JSONKeys {
        static let type = "typ"
        static let recipient = "key"
        static let data = "dat"
    }

    /// Encode to JSON dictionary
    public func toJSON() -> [String: Any] {
        var dict: [String: Any] = [
            JSONKeys.recipient: recipient.base64URLEncodedString(),
            JSONKeys.data: data.base64URLEncodedString()
        ]
        // Only include type if non-zero
        if type != 0 {
            dict[JSONKeys.type] = type
        }
        return dict
    }

    /// Decode from JSON dictionary
    public static func fromJSON(_ dict: [String: Any]) throws -> MessageRecipient {
        guard let recipientStr = dict[JSONKeys.recipient] as? String,
              let recipientData = Data(base64URLEncoded: recipientStr) else {
            throw BottleError.decodingFailed("MessageRecipient missing or invalid recipient")
        }

        guard let dataStr = dict[JSONKeys.data] as? String,
              let dataData = Data(base64URLEncoded: dataStr) else {
            throw BottleError.decodingFailed("MessageRecipient missing or invalid data")
        }

        let type = dict[JSONKeys.type] as? Int ?? 0

        return MessageRecipient(
            type: type,
            recipient: recipientData,
            data: dataData
        )
    }
}

// MARK: - Equatable

extension MessageRecipient: Equatable {
    public static func == (lhs: MessageRecipient, rhs: MessageRecipient) -> Bool {
        return lhs.type == rhs.type &&
               lhs.recipient == rhs.recipient &&
               lhs.data == rhs.data
    }
}
