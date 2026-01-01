import Foundation
import SwiftCBOR

/// A purpose-specific subkey in an IDCard
public struct SubKey: Sendable, Equatable {
    /// Public key in PKIX DER format
    public var key: Data

    /// When this subkey was added
    public var issued: Date

    /// Optional expiration time
    public var expires: Date?

    /// Purposes this key is authorized for
    public var purposes: [String]

    public init(key: Data, issued: Date = Date(), expires: Date? = nil, purposes: [String] = []) {
        self.key = key
        self.issued = issued
        self.expires = expires
        self.purposes = purposes
    }

    /// Create a subkey from a public key type
    public init(publicKey: PublicKeyType, issued: Date = Date(), expires: Date? = nil, purposes: [String] = []) throws {
        self.key = try marshalPKIXPublicKey(publicKey)
        self.issued = issued
        self.expires = expires
        self.purposes = purposes
    }

    /// Get the parsed public key
    public func publicKey() throws -> PublicKeyType {
        return try parsePKIXPublicKey(key)
    }

    /// Check if this key has the given purpose
    public func hasPurpose(_ purpose: String) -> Bool {
        return purposes.contains(purpose)
    }

    /// Check if this key is expired
    public var isExpired: Bool {
        guard let expires = expires else {
            return false
        }
        return Date() > expires
    }
}

// MARK: - CBOR Encoding (Integer-keyed map)

extension SubKey {
    /// CBOR integer keys
    private enum CBORKey: Int {
        case key = 1
        case issued = 2
        case expires = 3
        case purposes = 4
    }

    /// Encode to CBOR as integer-keyed map
    public func toCBOR() -> CBOR {
        var map: [CBOR: CBOR] = [:]

        map[.unsignedInt(UInt64(CBORKey.key.rawValue))] = .byteString(Array(key))
        map[.unsignedInt(UInt64(CBORKey.issued.rawValue))] = .unsignedInt(UInt64(issued.timeIntervalSince1970))

        if let expires = expires {
            map[.unsignedInt(UInt64(CBORKey.expires.rawValue))] = .unsignedInt(UInt64(expires.timeIntervalSince1970))
        }

        if !purposes.isEmpty {
            map[.unsignedInt(UInt64(CBORKey.purposes.rawValue))] = .array(purposes.map { .utf8String($0) })
        }

        return .map(map)
    }

    /// Decode from CBOR
    public static func fromCBOR(_ cbor: CBOR) throws -> SubKey {
        guard case .map(let map) = cbor else {
            throw BottleError.decodingFailed("SubKey must be a map")
        }

        // Parse key
        guard let keyValue = map[.unsignedInt(UInt64(CBORKey.key.rawValue))],
              case .byteString(let keyBytes) = keyValue else {
            throw BottleError.decodingFailed("SubKey missing key field")
        }

        // Parse issued
        let issued: Date
        if let issuedValue = map[.unsignedInt(UInt64(CBORKey.issued.rawValue))] {
            switch issuedValue {
            case .unsignedInt(let ts):
                issued = Date(timeIntervalSince1970: TimeInterval(ts))
            case .tagged(let tag, let content) where tag.rawValue == 0 || tag.rawValue == 1:
                if case .utf8String(let str) = content {
                    let formatter = ISO8601DateFormatter()
                    if let date = formatter.date(from: str) {
                        issued = date
                    } else {
                        throw BottleError.decodingFailed("Invalid timestamp format")
                    }
                } else if case .unsignedInt(let ts) = content {
                    issued = Date(timeIntervalSince1970: TimeInterval(ts))
                } else {
                    throw BottleError.decodingFailed("Invalid timestamp format")
                }
            default:
                throw BottleError.decodingFailed("SubKey invalid issued field")
            }
        } else {
            issued = Date()
        }

        // Parse expires (optional)
        var expires: Date?
        if let expiresValue = map[.unsignedInt(UInt64(CBORKey.expires.rawValue))] {
            switch expiresValue {
            case .unsignedInt(let ts):
                expires = Date(timeIntervalSince1970: TimeInterval(ts))
            case .tagged(let tag, let content) where tag.rawValue == 0 || tag.rawValue == 1:
                if case .utf8String(let str) = content {
                    let formatter = ISO8601DateFormatter()
                    expires = formatter.date(from: str)
                } else if case .unsignedInt(let ts) = content {
                    expires = Date(timeIntervalSince1970: TimeInterval(ts))
                }
            default:
                break
            }
        }

        // Parse purposes
        var purposes: [String] = []
        if let purposesValue = map[.unsignedInt(UInt64(CBORKey.purposes.rawValue))],
           case .array(let arr) = purposesValue {
            purposes = arr.compactMap {
                if case .utf8String(let str) = $0 {
                    return str
                }
                return nil
            }
        }

        return SubKey(
            key: Data(keyBytes),
            issued: issued,
            expires: expires,
            purposes: purposes
        )
    }
}

// MARK: - JSON Encoding

extension SubKey {
    private enum JSONKeys {
        static let key = "key"
        static let issued = "iss"
        static let expires = "exp"
        static let purposes = "pur"
    }

    public func toJSON() -> [String: Any] {
        var dict: [String: Any] = [
            JSONKeys.key: key.base64URLEncodedString()
        ]

        let formatter = ISO8601DateFormatter()
        dict[JSONKeys.issued] = formatter.string(from: issued)

        if let expires = expires {
            dict[JSONKeys.expires] = formatter.string(from: expires)
        }

        if !purposes.isEmpty {
            dict[JSONKeys.purposes] = purposes
        }

        return dict
    }

    public static func fromJSON(_ dict: [String: Any]) throws -> SubKey {
        guard let keyStr = dict[JSONKeys.key] as? String,
              let keyData = Data(base64URLEncoded: keyStr) else {
            throw BottleError.decodingFailed("SubKey missing or invalid key")
        }

        let formatter = ISO8601DateFormatter()

        let issued: Date
        if let issuedStr = dict[JSONKeys.issued] as? String,
           let date = formatter.date(from: issuedStr) {
            issued = date
        } else {
            issued = Date()
        }

        var expires: Date?
        if let expiresStr = dict[JSONKeys.expires] as? String {
            expires = formatter.date(from: expiresStr)
        }

        let purposes = dict[JSONKeys.purposes] as? [String] ?? []

        return SubKey(
            key: keyData,
            issued: issued,
            expires: expires,
            purposes: purposes
        )
    }
}
