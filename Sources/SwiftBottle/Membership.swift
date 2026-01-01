import Foundation
import SwiftCBOR
import CryptoKit
@preconcurrency import Security

/// Membership represents a group membership for an IDCard
public struct Membership: Sendable, Equatable {
    /// Member's IDCard self key (PKIX DER format)
    /// May be omitted when stored in IDCard's groups array
    public var subject: Data?

    /// Group's IDCard self key (PKIX DER format)
    public var key: Data

    /// Status: "valid" or "suspended"
    public var status: String

    /// When this membership was issued
    public var issued: Date

    /// Additional metadata
    public var info: [String: String]

    /// Signing key used (PKIX DER format)
    public var signKey: Data?

    /// Signature over membership data
    public var signature: Data?

    public init(
        subject: Data? = nil,
        key: Data,
        status: String = "valid",
        issued: Date = Date(),
        info: [String: String] = [:],
        signKey: Data? = nil,
        signature: Data? = nil
    ) {
        self.subject = subject
        self.key = key
        self.status = status
        self.issued = issued
        self.info = info
        self.signKey = signKey
        self.signature = signature
    }
}

// MARK: - Signing

extension Membership {
    /// Sign this membership with the given private key
    public mutating func sign(privateKey: PrivateKeyType) throws {
        // Prepare data for signing (canonical CBOR without signature fields)
        let signData = try prepareSignData()

        // Sign
        let signatureData = try SwiftBottle.sign(privateKey: privateKey, data: signData)

        // Store signature and signing key
        self.signKey = try marshalPKIXPublicKey(privateKey.publicKey)
        self.signature = signatureData
    }

    /// Verify this membership's signature
    public func verify() throws {
        guard let signKey = signKey, let signature = signature else {
            throw BottleError.verifyFailed
        }

        let signData = try prepareSignData()
        let publicKey = try parsePKIXPublicKey(signKey)
        try SwiftBottle.verify(publicKey: publicKey, data: signData, signature: signature)
    }

    /// Prepare the data to be signed (canonical CBOR)
    private func prepareSignData() throws -> Data {
        // Create a copy without signature fields for signing
        var signMap: [CBOR: CBOR] = [:]

        if let subject = subject {
            signMap[.unsignedInt(UInt64(CBORKey.subject.rawValue))] = .byteString(Array(subject))
        }
        signMap[.unsignedInt(UInt64(CBORKey.key.rawValue))] = .byteString(Array(key))
        signMap[.unsignedInt(UInt64(CBORKey.status.rawValue))] = .utf8String(status)
        signMap[.unsignedInt(UInt64(CBORKey.issued.rawValue))] = .unsignedInt(UInt64(issued.timeIntervalSince1970))

        if !info.isEmpty {
            var infoMap: [CBOR: CBOR] = [:]
            for (k, v) in info {
                infoMap[.utf8String(k)] = .utf8String(v)
            }
            signMap[.unsignedInt(UInt64(CBORKey.info.rawValue))] = .map(infoMap)
        }

        // Encode canonically
        let cbor = CBOR.map(signMap)
        return Data(cbor.encode())
    }
}

// MARK: - CBOR Encoding (Integer-keyed map)

extension Membership {
    /// CBOR integer keys
    fileprivate enum CBORKey: Int {
        case subject = 1
        case key = 2
        case status = 3
        case issued = 4
        case info = 5
        case signKey = 6
        case signature = 7
    }

    /// Encode to CBOR
    public func toCBOR(includeSubject: Bool = true) -> CBOR {
        var map: [CBOR: CBOR] = [:]

        if includeSubject, let subject = subject {
            map[.unsignedInt(UInt64(CBORKey.subject.rawValue))] = .byteString(Array(subject))
        }

        map[.unsignedInt(UInt64(CBORKey.key.rawValue))] = .byteString(Array(key))
        map[.unsignedInt(UInt64(CBORKey.status.rawValue))] = .utf8String(status)
        map[.unsignedInt(UInt64(CBORKey.issued.rawValue))] = .unsignedInt(UInt64(issued.timeIntervalSince1970))

        if !info.isEmpty {
            var infoMap: [CBOR: CBOR] = [:]
            for (k, v) in info {
                infoMap[.utf8String(k)] = .utf8String(v)
            }
            map[.unsignedInt(UInt64(CBORKey.info.rawValue))] = .map(infoMap)
        }

        if let signKey = signKey {
            map[.unsignedInt(UInt64(CBORKey.signKey.rawValue))] = .byteString(Array(signKey))
        }

        if let signature = signature {
            map[.unsignedInt(UInt64(CBORKey.signature.rawValue))] = .byteString(Array(signature))
        }

        return .map(map)
    }

    /// Decode from CBOR
    public static func fromCBOR(_ cbor: CBOR) throws -> Membership {
        guard case .map(let map) = cbor else {
            throw BottleError.decodingFailed("Membership must be a map")
        }

        // Parse subject (optional)
        var subject: Data?
        if let subjectValue = map[.unsignedInt(UInt64(CBORKey.subject.rawValue))],
           case .byteString(let bytes) = subjectValue {
            subject = Data(bytes)
        }

        // Parse key
        guard let keyValue = map[.unsignedInt(UInt64(CBORKey.key.rawValue))],
              case .byteString(let keyBytes) = keyValue else {
            throw BottleError.decodingFailed("Membership missing key")
        }

        // Parse status
        let status: String
        if let statusValue = map[.unsignedInt(UInt64(CBORKey.status.rawValue))],
           case .utf8String(let s) = statusValue {
            status = s
        } else {
            status = "valid"
        }

        // Parse issued
        let issued: Date
        if let issuedValue = map[.unsignedInt(UInt64(CBORKey.issued.rawValue))] {
            switch issuedValue {
            case .unsignedInt(let ts):
                issued = Date(timeIntervalSince1970: TimeInterval(ts))
            default:
                issued = Date()
            }
        } else {
            issued = Date()
        }

        // Parse info
        var info: [String: String] = [:]
        if let infoValue = map[.unsignedInt(UInt64(CBORKey.info.rawValue))],
           case .map(let infoMap) = infoValue {
            for (k, v) in infoMap {
                if case .utf8String(let key) = k,
                   case .utf8String(let value) = v {
                    info[key] = value
                }
            }
        }

        // Parse signKey
        var signKey: Data?
        if let signKeyValue = map[.unsignedInt(UInt64(CBORKey.signKey.rawValue))],
           case .byteString(let bytes) = signKeyValue {
            signKey = Data(bytes)
        }

        // Parse signature
        var signature: Data?
        if let signatureValue = map[.unsignedInt(UInt64(CBORKey.signature.rawValue))],
           case .byteString(let bytes) = signatureValue {
            signature = Data(bytes)
        }

        return Membership(
            subject: subject,
            key: Data(keyBytes),
            status: status,
            issued: issued,
            info: info,
            signKey: signKey,
            signature: signature
        )
    }
}

// MARK: - Factory Function

/// Create a new membership
public func newMembership(memberIDCard: IDCard, groupKey: Data) -> Membership {
    return Membership(
        subject: memberIDCard.selfKey,
        key: groupKey,
        status: "valid",
        issued: Date()
    )
}
