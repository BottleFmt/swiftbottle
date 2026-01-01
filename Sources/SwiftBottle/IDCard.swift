import Foundation
import SwiftCBOR
import CryptoKit
@preconcurrency import Security

/// IDCard represents a cryptographic identity with purpose-specific subkeys
public struct IDCard: @unchecked Sendable {
    /// Primary public key in PKIX DER format
    public var selfKey: Data

    /// When this IDCard was created
    public var issued: Date

    /// Subkeys with specific purposes
    public var subKeys: [SubKey]

    /// Revoked subkeys
    public var revoke: [SubKey]

    /// Group memberships
    public var groups: [Membership]

    /// Custom metadata
    public var meta: [String: String]

    public init(
        selfKey: Data,
        issued: Date = Date(),
        subKeys: [SubKey] = [],
        revoke: [SubKey] = [],
        groups: [Membership] = [],
        meta: [String: String] = [:]
    ) {
        self.selfKey = selfKey
        self.issued = issued
        self.subKeys = subKeys
        self.revoke = revoke
        self.groups = groups
        self.meta = meta
    }

    /// Create an IDCard from a public key
    public init(publicKey: PublicKeyType) throws {
        self.selfKey = try marshalPKIXPublicKey(publicKey)
        self.issued = Date()
        self.subKeys = [SubKey(key: self.selfKey, issued: self.issued, purposes: ["sign", "decrypt"])]
        self.revoke = []
        self.groups = []
        self.meta = [:]
    }

    /// Get the primary public key
    public func primaryKey() throws -> PublicKeyType {
        return try parsePKIXPublicKey(selfKey)
    }
}

// MARK: - Key Management

extension IDCard {
    /// Get all keys with the given purpose
    public func getKeys(purpose: String) -> [Data] {
        var result: [Data] = []

        for subKey in subKeys {
            // Skip expired keys
            if subKey.isExpired {
                continue
            }

            // Skip revoked keys
            if revoke.contains(where: { $0.key == subKey.key }) {
                continue
            }

            // Check purpose
            if subKey.hasPurpose(purpose) {
                result.append(subKey.key)
            }
        }

        return result
    }

    /// Get all public keys with the given purpose
    public func getPublicKeys(purpose: String) throws -> [PublicKeyType] {
        let keyData = getKeys(purpose: purpose)
        return try keyData.map { try parsePKIXPublicKey($0) }
    }

    /// Find a subkey by its key data
    public func findKey(_ key: Data) -> SubKey? {
        return subKeys.first { $0.key == key }
    }

    /// Find a subkey by public key type
    public func findKey(_ publicKey: PublicKeyType) -> SubKey? {
        guard let keyData = try? marshalPKIXPublicKey(publicKey) else {
            return nil
        }
        return findKey(keyData)
    }

    /// Add a purpose to a key
    public mutating func addKeyPurpose(_ key: Data, _ purposes: String...) throws {
        guard let index = subKeys.firstIndex(where: { $0.key == key }) else {
            throw BottleError.keyNotFound
        }

        for purpose in purposes {
            if !subKeys[index].purposes.contains(purpose) {
                subKeys[index].purposes.append(purpose)
            }
        }
    }

    /// Set the purposes for a key (replacing existing)
    public mutating func setKeyPurposes(_ key: Data, _ purposes: String...) throws {
        guard let index = subKeys.firstIndex(where: { $0.key == key }) else {
            throw BottleError.keyNotFound
        }

        subKeys[index].purposes = purposes
    }

    /// Test if a key has the given purpose
    public func testKeyPurpose(_ key: Data, _ purpose: String) throws {
        guard let subKey = findKey(key) else {
            throw BottleError.keyNotFound
        }

        if subKey.isExpired {
            throw BottleError.keyUnfit("Key is expired")
        }

        if revoke.contains(where: { $0.key == key }) {
            throw BottleError.keyUnfit("Key is revoked")
        }

        if !subKey.hasPurpose(purpose) {
            throw BottleError.keyUnfit("Key does not have purpose '\(purpose)'")
        }
    }

    /// Test if a public key type has the given purpose
    public func testKeyPurpose(_ publicKey: PublicKeyType, _ purpose: String) throws {
        guard let keyData = try? marshalPKIXPublicKey(publicKey) else {
            throw BottleError.keyNotFound
        }
        try testKeyPurpose(keyData, purpose)
    }
}

// MARK: - CBOR Encoding (Integer-keyed map)

extension IDCard {
    /// CBOR integer keys
    private enum CBORKey: Int {
        case selfKey = 1
        case issued = 2
        case subKeys = 3
        case revoke = 4
        case groups = 5
        case meta = 6
    }

    /// Encode to CBOR as integer-keyed map
    public func toCBOR() -> CBOR {
        var map: [CBOR: CBOR] = [:]

        map[.unsignedInt(UInt64(CBORKey.selfKey.rawValue))] = .byteString(Array(selfKey))
        map[.unsignedInt(UInt64(CBORKey.issued.rawValue))] = .unsignedInt(UInt64(issued.timeIntervalSince1970))

        if !subKeys.isEmpty {
            map[.unsignedInt(UInt64(CBORKey.subKeys.rawValue))] = .array(subKeys.map { $0.toCBOR() })
        }

        if !revoke.isEmpty {
            map[.unsignedInt(UInt64(CBORKey.revoke.rawValue))] = .array(revoke.map { $0.toCBOR() })
        }

        if !groups.isEmpty {
            map[.unsignedInt(UInt64(CBORKey.groups.rawValue))] = .array(groups.map { $0.toCBOR(includeSubject: false) })
        }

        if !meta.isEmpty {
            var metaMap: [CBOR: CBOR] = [:]
            for (key, value) in meta {
                metaMap[.utf8String(key)] = .utf8String(value)
            }
            map[.unsignedInt(UInt64(CBORKey.meta.rawValue))] = .map(metaMap)
        }

        return .map(map)
    }

    /// Decode from CBOR
    public static func fromCBOR(_ cbor: CBOR) throws -> IDCard {
        guard case .map(let map) = cbor else {
            throw BottleError.decodingFailed("IDCard must be a map")
        }

        // Parse selfKey
        guard let selfValue = map[.unsignedInt(UInt64(CBORKey.selfKey.rawValue))],
              case .byteString(let selfBytes) = selfValue else {
            throw BottleError.decodingFailed("IDCard missing self key")
        }

        // Parse issued
        let issued: Date
        if let issuedValue = map[.unsignedInt(UInt64(CBORKey.issued.rawValue))] {
            switch issuedValue {
            case .unsignedInt(let ts):
                issued = Date(timeIntervalSince1970: TimeInterval(ts))
            case .tagged(_, let content):
                if case .utf8String(let str) = content {
                    let formatter = ISO8601DateFormatter()
                    if let date = formatter.date(from: str) {
                        issued = date
                    } else {
                        issued = Date()
                    }
                } else if case .unsignedInt(let ts) = content {
                    issued = Date(timeIntervalSince1970: TimeInterval(ts))
                } else {
                    issued = Date()
                }
            default:
                issued = Date()
            }
        } else {
            issued = Date()
        }

        // Parse subKeys
        var subKeys: [SubKey] = []
        if let subKeysValue = map[.unsignedInt(UInt64(CBORKey.subKeys.rawValue))],
           case .array(let arr) = subKeysValue {
            subKeys = try arr.map { try SubKey.fromCBOR($0) }
        }

        // Parse revoke
        var revoke: [SubKey] = []
        if let revokeValue = map[.unsignedInt(UInt64(CBORKey.revoke.rawValue))],
           case .array(let arr) = revokeValue {
            revoke = try arr.map { try SubKey.fromCBOR($0) }
        }

        // Parse groups
        var groups: [Membership] = []
        if let groupsValue = map[.unsignedInt(UInt64(CBORKey.groups.rawValue))],
           case .array(let arr) = groupsValue {
            groups = try arr.map { try Membership.fromCBOR($0) }
        }

        // Parse meta
        var meta: [String: String] = [:]
        if let metaValue = map[.unsignedInt(UInt64(CBORKey.meta.rawValue))],
           case .map(let metaMap) = metaValue {
            for (key, value) in metaMap {
                if case .utf8String(let k) = key,
                   case .utf8String(let v) = value {
                    meta[k] = v
                }
            }
        }

        return IDCard(
            selfKey: Data(selfBytes),
            issued: issued,
            subKeys: subKeys,
            revoke: revoke,
            groups: groups,
            meta: meta
        )
    }

    /// Convert to CBOR bytes
    public func toCBORData() -> Data {
        return Data(toCBOR().encode())
    }
}

// MARK: - Signing and Loading

extension IDCard {
    /// Sign this IDCard and return the signed bottle CBOR
    public func sign(privateKey: PrivateKeyType) throws -> Data {
        // Create bottle with IDCard content
        let idcardCBOR = self.toCBORData()
        var bottle = Bottle(message: idcardCBOR, format: .clearText)
        bottle.header["ct"] = "idcard"

        // Bottle up to create nested structure
        try bottle.bottleUp()

        // Sign with the private key
        try bottle.sign(privateKey: privateKey)

        return try bottle.toCBOR()
    }

    /// Load an IDCard from a signed bottle
    public static func load(_ data: Data) throws -> IDCard {
        let bottle = try Bottle.fromCBOR(data)
        return try load(bottle: bottle)
    }

    /// Load an IDCard from a bottle
    public static func load(bottle: Bottle) throws -> IDCard {
        // Verify at least one signature
        guard !bottle.signatures.isEmpty else {
            throw BottleError.verifyFailed
        }

        // Verify all signatures
        for sig in bottle.signatures {
            try sig.verify(message: bottle.message)
        }

        // Get inner content
        var innerBottle = bottle
        while innerBottle.format != .clearText {
            switch innerBottle.format {
            case .cborBottle:
                innerBottle = try Bottle.fromCBOR(innerBottle.message)
            case .jsonBottle:
                innerBottle = try Bottle.fromJSON(innerBottle.message)
            default:
                throw BottleError.invalidFormat("Cannot load IDCard from encrypted bottle")
            }
        }

        // Check content type
        let ct = innerBottle.header["ct"] as? String ?? ""
        guard ct == "idcard" else {
            throw BottleError.invalidFormat("Bottle does not contain an IDCard (ct=\(ct))")
        }

        // Parse IDCard
        guard let cbor = try? CBOR.decode(Array(innerBottle.message)) else {
            throw BottleError.decodingFailed("Invalid IDCard CBOR")
        }

        let idcard = try IDCard.fromCBOR(cbor)

        // Verify that at least one signature matches the IDCard's self key
        let selfKeyPKIX = idcard.selfKey
        var foundMatch = false
        for sig in bottle.signatures {
            if sig.signer == selfKeyPKIX {
                foundMatch = true
                break
            }
        }

        // Also check subkeys with sign purpose
        if !foundMatch {
            for subKey in idcard.subKeys {
                if subKey.hasPurpose("sign") {
                    for sig in bottle.signatures {
                        if sig.signer == subKey.key {
                            foundMatch = true
                            break
                        }
                    }
                }
                if foundMatch { break }
            }
        }

        guard foundMatch else {
            throw BottleError.verifyFailed
        }

        return idcard
    }
}

// MARK: - KeyProvider Protocol

/// Protocol for objects that can provide keys for encryption
public protocol KeyProvider {
    func getKeys(purpose: String) -> [Data]
}

extension IDCard: KeyProvider {}

// MARK: - Factory Function

/// Create a new IDCard from a public key
public func newIDCard(_ publicKey: PublicKeyType) throws -> IDCard {
    return try IDCard(publicKey: publicKey)
}
