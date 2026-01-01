import Foundation
import SwiftCBOR

/// A signature entry in a Bottle
/// Contains the signer's public key and the signature data
public struct MessageSignature: Sendable {
    /// Signature type (0 = PKIX-encoded keys, the only type currently defined)
    public var type: Int

    /// Signer's public key in PKIX DER format
    public var signer: Data

    /// Signature value
    public var data: Data

    public init(type: Int = 0, signer: Data, data: Data) {
        self.type = type
        self.signer = signer
        self.data = data
    }
}

// MARK: - CBOR Encoding

extension MessageSignature {
    /// Encode to CBOR as an array [type, signer, data]
    public func toCBOR() -> CBOR {
        return .array([
            .unsignedInt(UInt64(type)),
            .byteString(Array(signer)),
            .byteString(Array(data))
        ])
    }

    /// Decode from CBOR array
    public static func fromCBOR(_ cbor: CBOR) throws -> MessageSignature {
        guard case .array(let arr) = cbor, arr.count == 3 else {
            throw BottleError.decodingFailed("MessageSignature must be a 3-element array")
        }

        guard case .unsignedInt(let typeVal) = arr[0] else {
            throw BottleError.decodingFailed("MessageSignature type must be an integer")
        }

        guard case .byteString(let signerBytes) = arr[1] else {
            throw BottleError.decodingFailed("MessageSignature signer must be a byte string")
        }

        guard case .byteString(let dataBytes) = arr[2] else {
            throw BottleError.decodingFailed("MessageSignature data must be a byte string")
        }

        return MessageSignature(
            type: Int(typeVal),
            signer: Data(signerBytes),
            data: Data(dataBytes)
        )
    }
}

// MARK: - JSON Encoding

extension MessageSignature {
    /// JSON keys
    private enum JSONKeys {
        static let type = "typ"
        static let signer = "key"
        static let data = "dat"
    }

    /// Encode to JSON dictionary
    public func toJSON() -> [String: Any] {
        var dict: [String: Any] = [
            JSONKeys.signer: signer.base64URLEncodedString(),
            JSONKeys.data: data.base64URLEncodedString()
        ]
        // Only include type if non-zero
        if type != 0 {
            dict[JSONKeys.type] = type
        }
        return dict
    }

    /// Decode from JSON dictionary
    public static func fromJSON(_ dict: [String: Any]) throws -> MessageSignature {
        guard let signerStr = dict[JSONKeys.signer] as? String,
              let signerData = Data(base64URLEncoded: signerStr) else {
            throw BottleError.decodingFailed("MessageSignature missing or invalid signer")
        }

        guard let dataStr = dict[JSONKeys.data] as? String,
              let dataData = Data(base64URLEncoded: dataStr) else {
            throw BottleError.decodingFailed("MessageSignature missing or invalid data")
        }

        let type = dict[JSONKeys.type] as? Int ?? 0

        return MessageSignature(
            type: type,
            signer: signerData,
            data: dataData
        )
    }
}

// MARK: - Equatable

extension MessageSignature: Equatable {
    public static func == (lhs: MessageSignature, rhs: MessageSignature) -> Bool {
        return lhs.type == rhs.type &&
               lhs.signer == rhs.signer &&
               lhs.data == rhs.data
    }
}
