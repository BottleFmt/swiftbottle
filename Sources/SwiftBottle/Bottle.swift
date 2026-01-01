import Foundation
import SwiftCBOR
import CryptoKit
@preconcurrency import Security

/// Bottle is a secure message container supporting encryption and signatures
/// It can contain raw data, CBOR/JSON encoded content, or encrypted content
public struct Bottle: @unchecked Sendable {
    /// Metadata header (not encrypted unless nested)
    public var header: [String: Any]

    /// Payload bytes
    public var message: Data

    /// Format indicating how message should be interpreted
    public var format: MessageFormat

    /// Recipients for encrypted messages (empty for cleartext)
    public var recipients: [MessageRecipient]

    /// Digital signatures
    public var signatures: [MessageSignature]

    /// Create a new bottle with the given data
    public init(
        header: [String: Any] = [:],
        message: Data = Data(),
        format: MessageFormat = .clearText,
        recipients: [MessageRecipient] = [],
        signatures: [MessageSignature] = []
    ) {
        self.header = header
        self.message = message
        self.format = format
        self.recipients = recipients
        self.signatures = signatures
    }

    /// Check if this is a "clean" bottle (cleartext with no signatures or recipients)
    public var isClean: Bool {
        return format == .clearText && recipients.isEmpty && signatures.isEmpty
    }
}

// MARK: - Factory Functions

/// Create a new bottle with raw data
public func newBottle(_ data: Data) -> Bottle {
    return Bottle(message: data, format: .clearText)
}

/// Create a bottle with CBOR-encoded data
public func wrap<T: Encodable>(_ value: T) throws -> Bottle {
    let encoder = JSONEncoder()
    let jsonData = try encoder.encode(value)

    // Convert JSON to CBOR via intermediate dictionary
    guard let jsonObject = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
        throw BottleError.encodingFailed("Failed to serialize value to dictionary")
    }

    let cbor = anyToCBOR(jsonObject)
    let cborData = Data(cbor.encode())

    var bottle = Bottle(message: cborData, format: .clearText)
    bottle.header["ct"] = "cbor"
    return bottle
}

/// Create a bottle with JSON-encoded data
public func wrapJSON<T: Encodable>(_ value: T) throws -> Bottle {
    let encoder = JSONEncoder()
    let jsonData = try encoder.encode(value)

    var bottle = Bottle(message: jsonData, format: .clearText)
    bottle.header["ct"] = "json"
    return bottle
}

/// Wrap existing CBOR data as a bottle
public func asCborBottle(_ data: Data) -> Bottle {
    var bottle = Bottle(message: data, format: .cborBottle)
    bottle.header["ct"] = "cbor"
    return bottle
}

/// Wrap existing JSON data as a bottle
public func asJsonBottle(_ data: Data) -> Bottle {
    var bottle = Bottle(message: data, format: .jsonBottle)
    bottle.header["ct"] = "json"
    return bottle
}

// MARK: - CBOR Encoding

extension Bottle {
    /// Encode bottle to CBOR bytes
    /// Format: [header, message, format, recipients, signatures]
    public func toCBOR() throws -> Data {
        let cbor = try toCBORValue()
        return Data(cbor.encode())
    }

    /// Convert to CBOR value
    internal func toCBORValue() throws -> CBOR {
        // Header as CBOR map
        let headerCBOR = anyToCBOR(header)

        // Message as byte string
        let messageCBOR = CBOR.byteString(Array(message))

        // Format as integer
        let formatCBOR = CBOR.unsignedInt(UInt64(format.rawValue))

        // Recipients: null if empty, otherwise array
        let recipientsCBOR: CBOR
        if recipients.isEmpty {
            recipientsCBOR = .null
        } else {
            recipientsCBOR = .array(recipients.map { $0.toCBOR() })
        }

        // Signatures: null if empty, otherwise array
        let signaturesCBOR: CBOR
        if signatures.isEmpty {
            signaturesCBOR = .null
        } else {
            signaturesCBOR = .array(signatures.map { $0.toCBOR() })
        }

        return .array([headerCBOR, messageCBOR, formatCBOR, recipientsCBOR, signaturesCBOR])
    }

    /// Decode bottle from CBOR bytes
    public static func fromCBOR(_ data: Data) throws -> Bottle {
        guard let cbor = try? CBOR.decode(Array(data)) else {
            throw BottleError.decodingFailed("Invalid CBOR data")
        }
        return try fromCBORValue(cbor)
    }

    /// Decode from CBOR value
    internal static func fromCBORValue(_ cbor: CBOR) throws -> Bottle {
        guard case .array(let arr) = cbor, arr.count == 5 else {
            throw BottleError.decodingFailed("Bottle must be a 5-element array")
        }

        // Parse header
        let header: [String: Any]
        switch arr[0] {
        case .map(let map):
            header = cborMapToDict(map)
        case .null:
            header = [:]
        default:
            throw BottleError.decodingFailed("Bottle header must be a map")
        }

        // Parse message
        guard case .byteString(let messageBytes) = arr[1] else {
            throw BottleError.decodingFailed("Bottle message must be a byte string")
        }

        // Parse format
        guard case .unsignedInt(let formatVal) = arr[2] else {
            throw BottleError.decodingFailed("Bottle format must be an integer")
        }
        guard let format = MessageFormat(rawValue: Int(formatVal)) else {
            throw BottleError.invalidFormat("Unknown format value: \(formatVal)")
        }

        // Parse recipients
        var recipients: [MessageRecipient] = []
        switch arr[3] {
        case .array(let recArr):
            recipients = try recArr.map { try MessageRecipient.fromCBOR($0) }
        case .null:
            recipients = []
        default:
            throw BottleError.decodingFailed("Bottle recipients must be an array or null")
        }

        // Parse signatures
        var signatures: [MessageSignature] = []
        switch arr[4] {
        case .array(let sigArr):
            signatures = try sigArr.map { try MessageSignature.fromCBOR($0) }
        case .null:
            signatures = []
        default:
            throw BottleError.decodingFailed("Bottle signatures must be an array or null")
        }

        return Bottle(
            header: header,
            message: Data(messageBytes),
            format: format,
            recipients: recipients,
            signatures: signatures
        )
    }
}

// MARK: - JSON Encoding

extension Bottle {
    /// JSON keys
    private enum JSONKeys {
        static let header = "hdr"
        static let message = "msg"
        static let format = "fmt"
        static let recipients = "dst"
        static let signatures = "sig"
    }

    /// Encode bottle to JSON bytes
    public func toJSON() throws -> Data {
        let dict = toJSONDict()
        return try JSONSerialization.data(withJSONObject: dict, options: [])
    }

    /// Convert to JSON dictionary
    internal func toJSONDict() -> [String: Any] {
        var dict: [String: Any] = [:]

        // Header (omit if empty)
        if !header.isEmpty {
            dict[JSONKeys.header] = header
        }

        // Message (always present)
        dict[JSONKeys.message] = message.base64URLEncodedString()

        // Format (omit if 0)
        if format.rawValue != 0 {
            dict[JSONKeys.format] = format.rawValue
        }

        // Recipients (omit if empty)
        if !recipients.isEmpty {
            dict[JSONKeys.recipients] = recipients.map { $0.toJSON() }
        }

        // Signatures (omit if empty)
        if !signatures.isEmpty {
            dict[JSONKeys.signatures] = signatures.map { $0.toJSON() }
        }

        return dict
    }

    /// Decode bottle from JSON bytes
    public static func fromJSON(_ data: Data) throws -> Bottle {
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw BottleError.decodingFailed("Invalid JSON data")
        }
        return try fromJSONDict(dict)
    }

    /// Decode from JSON dictionary
    internal static func fromJSONDict(_ dict: [String: Any]) throws -> Bottle {
        // Parse message (required)
        guard let messageStr = dict[JSONKeys.message] as? String,
              let messageData = Data(base64URLEncoded: messageStr) else {
            throw BottleError.decodingFailed("Bottle missing or invalid message")
        }

        // Parse header (optional)
        let header = dict[JSONKeys.header] as? [String: Any] ?? [:]

        // Parse format (optional, default 0)
        let formatRaw = dict[JSONKeys.format] as? Int ?? 0
        guard let format = MessageFormat(rawValue: formatRaw) else {
            throw BottleError.invalidFormat("Unknown format value: \(formatRaw)")
        }

        // Parse recipients (optional)
        var recipients: [MessageRecipient] = []
        if let recArr = dict[JSONKeys.recipients] as? [[String: Any]] {
            recipients = try recArr.map { try MessageRecipient.fromJSON($0) }
        }

        // Parse signatures (optional)
        var signatures: [MessageSignature] = []
        if let sigArr = dict[JSONKeys.signatures] as? [[String: Any]] {
            signatures = try sigArr.map { try MessageSignature.fromJSON($0) }
        }

        return Bottle(
            header: header,
            message: messageData,
            format: format,
            recipients: recipients,
            signatures: signatures
        )
    }
}

// MARK: - Nesting Operations

extension Bottle {
    /// Encapsulate the current bottle within a new bottle
    /// This preserves signatures and header in the nested structure
    public mutating func bottleUp() throws {
        let cborData = try self.toCBOR()

        self.header = [:]
        self.message = cborData
        self.format = .cborBottle
        self.recipients = []
        self.signatures = []
    }

    /// Extract the child bottle if this is a nested bottle
    public func child() throws -> Bottle {
        switch format {
        case .clearText:
            throw BottleError.invalidBottle("Cannot get child of cleartext bottle")
        case .cborBottle:
            return try Bottle.fromCBOR(message)
        case .jsonBottle:
            return try Bottle.fromJSON(message)
        case .aes:
            throw BottleError.invalidBottle("Cannot get child of encrypted bottle without decryption")
        }
    }
}

// MARK: - Encryption Operations

extension Bottle {
    /// Encrypt the bottle for the given recipients
    /// The bottle must be clean (cleartext with no signatures) or will be bottled up first
    public mutating func encrypt(_ recipients: PublicKeyType...) throws {
        try encrypt(recipients: recipients)
    }

    /// Encrypt the bottle for the given recipients array
    public mutating func encrypt(recipients: [PublicKeyType]) throws {
        guard !recipients.isEmpty else {
            throw BottleError.encryptNoRecipient
        }

        // If not clean, bottle up first to preserve signatures
        if !isClean {
            try bottleUp()
        }

        // Ensure we're in CBOR format for encryption
        if format == .clearText {
            try bottleUp()
        }

        // Generate random 32-byte AES key
        var aesKey = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, aesKey.count, &aesKey) == errSecSuccess else {
            throw BottleError.cryptoError("Failed to generate random AES key")
        }
        defer { memclr(&aesKey) }

        // Generate random 12-byte nonce
        var nonceBytes = [UInt8](repeating: 0, count: 12)
        guard SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes) == errSecSuccess else {
            throw BottleError.cryptoError("Failed to generate random nonce")
        }

        // Encrypt message with AES-256-GCM
        let symmetricKey = SymmetricKey(data: Data(aesKey))
        let nonce = try AES.GCM.Nonce(data: Data(nonceBytes))
        let sealed = try AES.GCM.seal(message, using: symmetricKey, nonce: nonce)

        // Build encrypted message: nonce || ciphertext || tag
        var encryptedMessage = Data(nonceBytes)
        encryptedMessage.append(sealed.ciphertext)
        encryptedMessage.append(sealed.tag)

        // Encrypt AES key for each recipient
        var messageRecipients: [MessageRecipient] = []
        for recipientKey in recipients {
            let encryptedKey = try encryptShortBuffer(data: Data(aesKey), publicKey: recipientKey)
            let recipientPKIX = try marshalPKIXPublicKey(recipientKey)

            messageRecipients.append(MessageRecipient(
                type: 0,
                recipient: recipientPKIX,
                data: encryptedKey
            ))
        }

        // Update bottle
        self.message = encryptedMessage
        self.format = .aes
        self.recipients = messageRecipients
        // Signatures are cleared (they're preserved in the nested bottle)
        self.signatures = []
    }

    /// Decrypt the bottle using the given private key
    /// Returns the decrypted inner bottle
    internal func decrypt(privateKey: PrivateKeyType) throws -> Bottle {
        guard format == .aes else {
            throw BottleError.invalidFormat("Cannot decrypt non-AES bottle")
        }

        // Find matching recipient
        let publicKeyPKIX = try marshalPKIXPublicKey(privateKey.publicKey)

        var encryptedAESKey: Data?
        for recipient in recipients {
            if recipient.recipient == publicKeyPKIX {
                encryptedAESKey = recipient.data
                break
            }
        }

        // If not found by exact match, try decrypting each
        if encryptedAESKey == nil {
            for recipient in recipients {
                if let _ = try? decryptShortBuffer(data: recipient.data, privateKey: privateKey) {
                    encryptedAESKey = recipient.data
                    break
                }
            }
        }

        guard let keyData = encryptedAESKey else {
            throw BottleError.noAppropriateKey
        }

        // Decrypt AES key
        var aesKey = try decryptShortBuffer(data: keyData, privateKey: privateKey)
        defer { memclr(&aesKey) }

        // Parse encrypted message: nonce (12) || ciphertext || tag (16)
        guard message.count > 28 else {
            throw BottleError.decodingFailed("Encrypted message too short")
        }

        let nonceBytes = message.prefix(12)
        let ciphertextAndTag = message.suffix(from: 12)
        let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)

        // Decrypt with AES-256-GCM
        let symmetricKey = SymmetricKey(data: aesKey)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

        // Parse inner bottle
        return try Bottle.fromCBOR(plaintext)
    }
}

// MARK: - CBOR Helpers

/// Convert Swift Any to CBOR
internal func anyToCBOR(_ value: Any) -> CBOR {
    switch value {
    case let v as Bool:
        return .boolean(v)
    case let v as Int:
        if v >= 0 {
            return .unsignedInt(UInt64(v))
        } else {
            return .negativeInt(UInt64(-1 - v))
        }
    case let v as UInt64:
        return .unsignedInt(v)
    case let v as Double:
        return .double(v)
    case let v as Float:
        return .float(v)
    case let v as String:
        return .utf8String(v)
    case let v as Data:
        return .byteString(Array(v))
    case let v as [UInt8]:
        return .byteString(v)
    case let v as [Any]:
        return .array(v.map { anyToCBOR($0) })
    case let v as [String: Any]:
        var pairs: [CBOR: CBOR] = [:]
        for (key, val) in v {
            pairs[.utf8String(key)] = anyToCBOR(val)
        }
        return .map(pairs)
    case is NSNull:
        return .null
    default:
        // Try to convert to string as fallback
        return .utf8String(String(describing: value))
    }
}

/// Convert CBOR map to Swift dictionary
internal func cborMapToDict(_ map: [CBOR: CBOR]) -> [String: Any] {
    var result: [String: Any] = [:]
    for (key, value) in map {
        guard case .utf8String(let keyStr) = key else {
            continue // Skip non-string keys
        }
        result[keyStr] = cborToAny(value)
    }
    return result
}

/// Convert CBOR to Swift Any
internal func cborToAny(_ cbor: CBOR) -> Any {
    switch cbor {
    case .boolean(let v):
        return v
    case .unsignedInt(let v):
        return Int(v)
    case .negativeInt(let v):
        return -1 - Int(v)
    case .double(let v):
        return v
    case .float(let v):
        return v
    case .half(let v):
        return v
    case .utf8String(let v):
        return v
    case .byteString(let v):
        return Data(v)
    case .array(let v):
        return v.map { cborToAny($0) }
    case .map(let v):
        return cborMapToDict(v)
    case .null, .undefined:
        return NSNull()
    case .simple(let v):
        return Int(v)
    case .tagged(_, let content):
        return cborToAny(content)
    case .date(let d):
        return d
    case .break:
        return NSNull()
    }
}

// MARK: - Equatable (partial - header comparison is limited)

extension Bottle: Equatable {
    public static func == (lhs: Bottle, rhs: Bottle) -> Bool {
        // Note: Header comparison is imperfect due to Any type
        return lhs.message == rhs.message &&
               lhs.format == rhs.format &&
               lhs.recipients == rhs.recipients &&
               lhs.signatures == rhs.signatures
    }
}
