import Foundation

// MARK: - Base64URL Encoding

extension Data {
    /// Encode to base64url without padding (RFC 4648 Section 5)
    public func base64URLEncodedString() -> String {
        var result = self.base64EncodedString()
        // Replace + with - and / with _
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        // Remove padding
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }

    /// Initialize from base64url encoded string (with or without padding)
    public init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let paddingLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: paddingLength)

        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        self = data
    }
}

// MARK: - Varint Encoding (Go-compatible)

/// Encode an integer as a varint (Go-compatible format)
public func encodeVarint(_ value: UInt64) -> Data {
    var result = Data()
    var v = value

    while v >= 0x80 {
        result.append(UInt8(v & 0x7F) | 0x80)
        v >>= 7
    }
    result.append(UInt8(v))

    return result
}

/// Decode a varint from data, returning the value and bytes consumed
public func decodeVarint(_ data: Data) throws -> (value: UInt64, bytesRead: Int) {
    var value: UInt64 = 0
    var shift: UInt64 = 0
    var bytesRead = 0

    for byte in data {
        bytesRead += 1
        value |= UInt64(byte & 0x7F) << shift

        if byte & 0x80 == 0 {
            return (value, bytesRead)
        }

        shift += 7
        if shift >= 64 {
            throw BottleError.decodingFailed("Varint overflow")
        }
    }

    throw BottleError.decodingFailed("Incomplete varint")
}

// MARK: - Secure Memory Clearing

/// Clear sensitive data from memory
/// Note: Swift does not guarantee this will prevent copies, but it's defense in depth
public func memclr(_ data: inout Data) {
    data.withUnsafeMutableBytes { ptr in
        if let baseAddress = ptr.baseAddress {
            memset(baseAddress, 0, ptr.count)
        }
    }
}

/// Clear sensitive data from an array
public func memclr(_ data: inout [UInt8]) {
    for i in data.indices {
        data[i] = 0
    }
}
