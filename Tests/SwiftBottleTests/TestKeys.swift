import Foundation
import CryptoKit
@testable import SwiftBottle

/// Shared test keys matching Go and Python implementations
enum TestKeys {
    // Alice: ECDSA P-256 (EC private key format)
    static let aliceDER = Data(base64URLEncoded: "MHcCAQEEIIaSb1TJIeVordec4nMPaRBMsoroc462mpeWDuMEhY1-oAoGCCqGSM49AwEHoUQDQgAE09oIghTDnluvtv0-NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE-KYA")!

    // Bob: ECDSA P-256 (EC private key format)
    static let bobDER = Data(base64URLEncoded: "MHcCAQEEIIPJmeofQddlqI3MNJEBcjEVhNjoR-aYpJXLa3X2q40koAoGCCqGSM49AwEHoUQDQgAEigRCfu95oGP9FNSLWoxhhCDEmgxYG8tMwlFItzAuV6W_fw0Og2BNG3yc0qOb-cEJjQKWRI9i_m1FUc97ajaTrg")!

    // Chloe: Ed25519 (PKCS8 format)
    static let chloeDER = Data(base64URLEncoded: "MC4CAQAwBQYDK2VwBCIEIPFWBuWK8Ms8fdCdVogl7elV1H56AxiUHMsGl85l4NTB")!

    // Daniel: Ed25519 (PKCS8 format)
    static let danielDER = Data(base64URLEncoded: "MC4CAQAwBQYDK2VwBCIEIMyPtgaGrXQ7VwAaZ-7cnwWQaAUpD4mQNzVo0-42CZ5V")!

    /// Get Alice's private key
    static func getAlice() throws -> PrivateKeyType {
        return try parsePKIXPrivateKey(aliceDER)
    }

    /// Get Bob's private key
    static func getBob() throws -> PrivateKeyType {
        return try parsePKIXPrivateKey(bobDER)
    }

    /// Get Chloe's private key
    static func getChloe() throws -> PrivateKeyType {
        return try parsePKIXPrivateKey(chloeDER)
    }

    /// Get Daniel's private key
    static func getDaniel() throws -> PrivateKeyType {
        return try parsePKIXPrivateKey(danielDER)
    }

    /// Get Alice's public key
    static func getAlicePublic() throws -> PublicKeyType {
        return try getAlice().publicKey
    }

    /// Get Bob's public key
    static func getBobPublic() throws -> PublicKeyType {
        return try getBob().publicKey
    }

    /// Get Chloe's public key
    static func getChloePublic() throws -> PublicKeyType {
        return try getChloe().publicKey
    }

    /// Get Daniel's public key
    static func getDanielPublic() throws -> PublicKeyType {
        return try getDaniel().publicKey
    }
}

/// Pre-generated test vectors from Go implementation
enum TestVectors {
    // Bottles
    static let aliceSignedCleartext = Data(base64Encoded: "haBRSGVsbG8gZnJvbSBBbGljZSEA9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIQCPEWPr/SDCeJXS73kn0oQwXWH70EfgSPtlhyLhvRHHYQIgbvITapFSnsuY2dAQorY+mTLOsMYOJB95nucHxIOzUME=")!

    static let chloeSignedCleartext = Data(base64Encoded: "haBRSGVsbG8gZnJvbSBDaGxvZSEA9oGDAFgsMCowBQYDK2VwAyEATL6PjuPHSTIG2UXmJfEMvJESSp7zLqTncBBc4ElE/D5YQPMG5xy/onBTIEHWfvlayb3lCTfGSClApscby4WP919SOs7c5iq7xsLrYkcGpwGCFKObAbT1C0+omag8EiDWNwY=")!

    static let aliceToBobEncrypted = Data(base64Encoded: "haBZAUSFoFhDm5+MnDHvHavDG26WIRahkvXRyopa5BCzFgv25By0k3ase9e/d7hvr+Eq7wKobH/11VQkZmc6gel8TtIAuutYZ7ZmqgKBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YmQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu2rfO4Mdj5HJ+ahL7WVbBZXrSzD2FoOOAjqFQ7PDTSfIucQV0gWOjLjPLg7SQ5yiO3pv1RKzJLotq6UyKA3B6iMtBkT4Sn0fVU2Nw0fw0bBjZFj1MPCFnXGqK9Qd3/EyzTA5XzksY+EZaBkOej1ckTc1fpXTEn8HZuPa/PYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIGgCMEL82ywkMC0PuAf4HUqS1wmnzXTtzUHSBy5Aok4ZAiEAn7pHkUVyWhCfb/aiGvwm0PW347iaKDOmywOwrZG1YNk=")!

    static let chloeToDanielEncrypted = Data(base64Encoded: "haBY6YWgWEbOz5dzuHVoDJGbbegel6QHqyxa7U7NuVznwNxeCQvqTgz8gEPb38MMsTxq5IR+Qu9cfgZ2a2/2DQg+0oJJPRl7ZUYrekXAAoGDAFgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+79YagAsMCowBQYDK2VuAyEAA943R8RqHeZffQ+TH4RlmrtXvklkBdKgddPyttXfvCxrZFHDb9X2oVfQRCbb4fIjc0VqVZT5HvVKf9bz+ymcWbkv+iWCc/Q+B8oLHebH9sE+0zytOy/e1Kamcir2AfaBgwBYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+WECeTEDNYixOSd2tj7BchCLVoLCkmr84L9CwxLo10mYgQoW5wZFOUEME0VdL3kaJfeHuX2/UiRWMk3rssnp6lJgO")!

    static let aliceToBobAndDaniel = Data(base64Encoded: "haBZAdmFoFg8uyjLChvFnHR+sq8bfbuziw/PeYrFriKzQSqZzQV3RWwGMsB1pz6hE9FnMqoIamLD2oM1HsHy1+GU8RERAoKDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEigRCfu95oGP9FNSLWoxhhCDEmgxYG8tMwlFItzAuV6W/fw0Og2BNG3yc0qOb+cEJjQKWRI9i/m1FUc97ajaTrliZAFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARF6feIhWN/vC1edEjEccG0ajlShDmBYyIrat0c+fz+yy43aIzQJKC5QQRpf8fG57Y5wZb3KhQIg63NOkYe3tIB1bsrUSWZUw/6uHoWAM1GT+oasplV4WxkRWzetoxH6vWtuRQgMzDTv9qjfSchaHpQgjMaPTknIqHNC8uRgwBYLDAqMAUGAytlcAMhAPZVf8q8vlzLzBqsIVEF3n/txTowBg+DI/4MaCTd1/u/WGoALDAqMAUGAytlbgMhAFuGnMFD6MCASWo8xOy9HSITAxPzu2UJuXSUCzRyZqYmy1uE1/Y7w1a3kOhitndcYPSMGnE7AKJmnjiAyf8vPnvv5ijUQlrm1Zcy+QavS33BopdG1HXKYxn6pF1r9gH2gYMAWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgWEcwRQIge6OK+2IEUVmPo7ZSovRJ5IJb9dZTT2ZcGgp4A2erM80CIQC3HMt9VGk0+tpEyripSdfobx1TcRByY3CI6Gbr2sZjiA==")!

    static let anonymousToBob = Data(base64Encoded: "haBYOYK78ifrqu7W6Uh3vF7PnqUr8CNJ5cezriuZb+EzFZ/NdacKr6s37y5jRbnOw5seoUtp54ClCJjzWgKBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YmQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4gO8JMnJc1wZLg7Ne1Ze3I4yKe7J7yRVnJTYe0PEkO8/61OFivv5YcdNZjNSoRvZx0O0KJEP7u1CtHDQPYcXbaGBQU/XVmP1NY0yepic+jWelsZNO8HScpaNY4HNtghcanOY0GDoZkokU5lvJzUARx1pmoowtqgSFkm6b/Y=")!

    static let aliceAndChloeSigned = Data(base64Encoded: "haBYHlNpZ25lZCBieSBib3RoIEFsaWNlIGFuZCBDaGxvZQD2goMAWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgWEYwRAIgKfCLaGT93SX/tGQvesD5y+XCNVLlcO9k2NJqVpA/IrYCIEnrnZ+9YdAGCjBvGt8IkPEJmrKpbDOlDx4zRr7WkYmngwBYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+WEBSiwkh3t4Q+Nrq/bRc6HNSjpJUo8GS22KgaJlUxAPnB8BfnOrp/zs07hJRgvtOrIy96BSRzDZSdDlNCpJ21zoE")!

    static let nestedBobThenDaniel = Data(base64Encoded: "haBZAfyFoFkBWCYLkGEdT1Q7jJSGLAzAIZmXKmTQF9XDNNm9IGRxFJQaXYkhdyO4z67pw8Nrb6OZwRUNCvC12qYkW9iZdypuw8seyMwA7SAtXRsJTDpXF3WSauqwr7ayvurrzxSThFoQfWhJ71Eb2WrzwDmROYvl4Wm2ooAKzxYuutKjKuzVF5VeF0m3scOSjHlP7KSF3vo3GyAMLhVHBYeLx7MvrVxY98BxB09oED4GhlIKzq8BIcdHYmkn8ckhH8APwx/oHaBKI/m7ppBTUdqW9qIPAn/CJb7r6pZlvVx/oepDoH5291BJCj/YHTm/V+VCA9iGnw+3Oac+M4krD5/tiPph3yDsgGVg2SzF8S2FrhHd4b1tfqBMzecKcAhgFFHaZcP7hyVSVPry/QnkcSI85fKdgpQnyfoGGb1a9usdOMyQAW0G8ywIiI/IpU1Pm7rGQaQ3wlh25FYiC6ZfglvpAoGDAFgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+79YagAsMCowBQYDK2VuAyEAK7KqTeAgS1FkPMGF2jgEny1TmvsxRx3H70OLhhKy73oeSpRThl/5KQGRuuYDWDW4kyFrXjqJd7F0gzgSzOYD2QBIkKESzYHSPDr9xdGTnO43jC0tan2NKaFuCY32AfaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimBYRjBEAiAT7cGQNP43M/T+L3Ve1LBpMF2cb4WySB1g3qHXotcOdwIgDbXdEgVyXMM/j5rfIL+cIvck2SYfTdnA4zpYYctUNxA=")!

    // IDCards
    static let aliceIDCard = Data(base64Encoded: "haBY/YWhYmN0ZmlkY2FyZFjspgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimACGmk+hQMDgaMBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgAhppPoUDBIJnZGVjcnlwdGRzaWduBPYF9gahZG5hbWVlQWxpY2UA9vYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIAM0VfD5ON6ajKxrR2sMcqlU+karsg4ha+HRWVJsPjWvAiEAlAx6nGF3vHDvV2wlzQ2qgwDuOXQ1dulxuZI+2UEL26Q=")!

    static let bobIDCard = Data(base64Encoded: "haBY+4WhYmN0ZmlkY2FyZFjqpgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k64CGmk+hQMDgaMBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASKBEJ+73mgY/0U1ItajGGEIMSaDFgby0zCUUi3MC5Xpb9/DQ6DYE0bfJzSo5v5wQmNApZEj2L+bUVRz3tqNpOuAhppPoUDBIJnZGVjcnlwdGRzaWduBPYF9gahZG5hbWVjQm9iAPb2AfaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YRzBFAiEAufvr4HAcHDhwD7zrCXHfzqGbNCJKf2HzSVPMXEARoRYCIEZnD7EobO3zNmDSJLXf6mMi4WWqr9qLEwl3poV/x9wv")!

    static let chloeIDCard = Data(base64Encoded: "haBYn4WhYmN0ZmlkY2FyZFiOpgFYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+AhppPoUDA4GjAVgsMCowBQYDK2VwAyEATL6PjuPHSTIG2UXmJfEMvJESSp7zLqTncBBc4ElE/D4CGmk+hQMEgmdkZWNyeXB0ZHNpZ24E9gX2BqFkbmFtZWVDaGxvZQD29gH2gYMAWCwwKjAFBgMrZXADIQBMvo+O48dJMgbZReYl8Qy8kRJKnvMupOdwEFzgSUT8PlhAzjf6zY5rD2kD0/12qFbscTK6Ib6OsssCoZaIyNpDOKFGLMTiMGHS3k+Ha9bHGcBo/DuoSWuDrxj/WThyRx0YBA==")!

    static let danielIDCard = Data(base64Encoded: "haBYoIWhYmN0ZmlkY2FyZFiPpgFYLDAqMAUGAytlcAMhAPZVf8q8vlzLzBqsIVEF3n/txTowBg+DI/4MaCTd1/u/AhppPoUDA4GjAVgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+78CGmk+hQMEgmdkZWNyeXB0ZHNpZ24E9gX2BqFkbmFtZWZEYW5pZWwA9vYB9oGDAFgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+79YQH4yeA5Oluwr9Av5EjDcMBo11ax2eNKVtDvLK37V4DCMr6rF4y41oRXiud9sr4Lwg0AGeW+OE9S14N5Emzj4GQQ=")!
}
