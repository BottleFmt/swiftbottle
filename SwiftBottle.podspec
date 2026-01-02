Pod::Spec.new do |s|
  s.name         = 'SwiftBottle'
  s.version      = '0.1.0'
  s.summary      = 'Swift implementation of the Bottle secure message container protocol'
  s.description  = <<-DESC
    SwiftBottle is a Swift implementation of the Bottle protocol (IETF draft-karpeles-bottle-idcard-01),
    providing a unified secure message container format with support for:
    - Multi-recipient encryption using AES-256-GCM
    - Multiple digital signatures (Ed25519, ECDSA P-256, RSA)
    - Recursive nesting for complex security arrangements
    - CBOR and JSON encodings
    - IDCard identity management with purpose-specific subkeys
  DESC

  s.homepage     = 'https://github.com/BottleFmt/swiftbottle'
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { 'Karpeles Lab Inc' => 'info@karpeleslabs.com' }
  s.source       = { :git => 'https://github.com/BottleFmt/swiftbottle.git', :tag => s.version.to_s }

  s.ios.deployment_target = '14.0'
  s.osx.deployment_target = '11.0'
  s.tvos.deployment_target = '14.0'
  # watchOS not supported due to SwiftCBOR dependency

  s.swift_version = '5.5'

  s.source_files = 'Sources/SwiftBottle/**/*.swift'

  s.dependency 'SwiftCBOR', '~> 0.4'

  s.frameworks = 'CryptoKit', 'Security'
end
