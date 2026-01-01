# SwiftBottle

Swift implementation of the Bottle protocol ([draft-karpeles-bottle-idcard-01](https://github.com/BottleFmt/bottle-id)), providing a unified secure message container format.

## Features

- **Multi-recipient encryption** using AES-256-GCM
- **Multiple digital signatures** (Ed25519, ECDSA P-256, RSA)
- **Recursive nesting** for complex security arrangements (sign-then-encrypt, etc.)
- **CBOR and JSON encodings**
- **IDCard identity management** with purpose-specific subkeys
- Full interoperability with [gobottle](https://github.com/BottleFmt/gobottle) (Go) and [pybottle](https://github.com/BottleFmt/pybottle) (Python)

## Requirements

- iOS 14.0+ / macOS 11.0+ / tvOS 14.0+ / watchOS 7.0+
- Swift 5.5+

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/BottleFmt/swiftbottle.git", from: "0.1.0")
]
```

### CocoaPods

Add to your `Podfile`:

```ruby
pod 'SwiftBottle', '~> 0.1.0'
```

## Usage

### Creating a Signed Message

```swift
import SwiftBottle

// Create a bottle with a message
var bottle = newBottle("Hello, World!".data(using: .utf8)!)

// Sign with a private key
try bottle.sign(privateKey: myPrivateKey)

// Serialize to CBOR
let data = try bottle.toCBOR()
```

### Creating an Encrypted Message

```swift
import SwiftBottle

// Create and encrypt for one or more recipients
var bottle = newBottle("Secret message".data(using: .utf8)!)
try bottle.encrypt(recipientPublicKey)

// Or for multiple recipients
try bottle.encrypt(recipients: [bob.publicKey, alice.publicKey])

let data = try bottle.toCBOR()
```

### Sign-Then-Encrypt Pattern

```swift
import SwiftBottle

var bottle = newBottle("Signed and encrypted".data(using: .utf8)!)

// Sign the message
try bottle.sign(privateKey: senderPrivateKey)

// Wrap into a nested bottle
try bottle.bottleUp()

// Encrypt the signed bottle
try bottle.encrypt(recipientPublicKey)

let data = try bottle.toCBOR()
```

### Opening a Bottle

```swift
import SwiftBottle

// Create an opener with your private keys
let keychain = Keychain()
try keychain.addKey(myPrivateKey)
let opener = Opener(keychain: keychain)

// Open a CBOR-encoded bottle
let (message, result) = try opener.openCBOR(data)

// Check signatures
if result.signedBy(expectedSenderPublicKey) {
    print("Verified signature from expected sender")
}

// Check decryption count
print("Decrypted \(result.decryptionCount) layer(s)")
```

### Working with IDCards

```swift
import SwiftBottle

// Create a new IDCard
var idcard = try IDCard(publicKey: myPublicKey)
idcard.meta["name"] = "Alice"

// Sign and serialize
let signedData = try idcard.sign(privateKey: myPrivateKey)

// Load an IDCard
let loaded = try IDCard.load(signedData)
print(loaded.meta["name"])  // "Alice"

// Check key purposes
try loaded.testKeyPurpose(somePublicKey, "sign")
try loaded.testKeyPurpose(somePublicKey, "decrypt")
```

## API Reference

### Bottle

```swift
// Create a new bottle
func newBottle(_ data: Data) -> Bottle

// Bottle struct
struct Bottle {
    var header: [String: Any]
    var message: Data
    var format: MessageFormat
    var recipients: [MessageRecipient]
    var signatures: [MessageSignature]

    mutating func encrypt(_ recipients: PublicKeyType...) throws
    mutating func encrypt(recipients: [PublicKeyType]) throws
    mutating func sign(privateKey: PrivateKeyType) throws
    mutating func bottleUp() throws
    func child() throws -> Bottle
    func toCBOR() throws -> Data
    func toJSON() throws -> Data
    static func fromCBOR(_ data: Data) throws -> Bottle
    static func fromJSON(_ data: Data) throws -> Bottle
}
```

### Opener

```swift
// Create an opener with private keys
let opener = Opener(keychain: keychain)

// Or use the empty opener for signature verification only
let emptyOpener = Opener()

// Open bottles
func open(_ bottle: Bottle) throws -> (Data, OpenResult)
func openCBOR(_ data: Data) throws -> (Data, OpenResult)
func openJSON(_ data: Data) throws -> (Data, OpenResult)
```

### OpenResult

```swift
struct OpenResult {
    var decryptionCount: Int
    var signatures: [MessageSignature]
    var bottles: [Bottle]

    func signedBy(_ key: PublicKeyType) -> Bool
}
```

### IDCard

```swift
struct IDCard {
    var meta: [String: String]

    init(publicKey: PublicKeyType) throws
    static func load(_ data: Data) throws -> IDCard
    func getKeys(purpose: String) -> [PublicKeyType]
    mutating func addKeyPurpose(_ key: PublicKeyType, purposes: [String]) throws
    func testKeyPurpose(_ key: PublicKeyType, _ purpose: String) throws
    func sign(privateKey: PrivateKeyType) throws -> Data
}
```

### Errors

```swift
enum BottleError: Error {
    case noAppropriateKey
    case verifyFailed
    case keyNotFound
    case keyUnfit
    case encryptNoRecipient
    case invalidFormat
    case decodingFailed(String)
}
```

## Supported Key Types

| Algorithm | Signing | Encryption |
|-----------|---------|------------|
| Ed25519 | Yes | Yes (via X25519) |
| ECDSA P-256 | Yes | Yes (via ECDH) |
| RSA | Yes | Yes (RSA-OAEP) |
| X25519 | No | Yes |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [gobottle](https://github.com/BottleFmt/gobottle) - Go implementation
- [pybottle](https://github.com/BottleFmt/pybottle) - Python implementation
- [bottle-id](https://github.com/BottleFmt/bottle-id) - Protocol specification (IETF draft)
