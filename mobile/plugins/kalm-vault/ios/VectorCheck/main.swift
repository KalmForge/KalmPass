// Checks the Swift port against ciphertext made by public/js/crypto.js.
// CI compiles this together with KalmVaultCore for macOS and runs it:
//
//   swiftc ios/Sources/KalmVaultCore/*.swift ios/VectorCheck/main.swift -o vector-check
//   ./vector-check test-vectors.json

import Foundation

struct Vectors: Decodable {
    struct Expected: Decodable {
        let id, name, username, password, url: String
    }
    let secret: String
    let wrappedKey: String
    let items: [VaultItem]
    let expected: [Expected]
}

let path = CommandLine.arguments.dropFirst().first ?? "test-vectors.json"
let vectors = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: URL(fileURLWithPath: path)))

var failures = 0
func check(_ name: String, _ passed: Bool) {
    print("\(passed ? "  ok  " : "FAIL  ")\(name)")
    if !passed { failures += 1 }
}

let logins = try VaultCrypto.decryptVault(
    secretBase64: vectors.secret,
    wrappedKey: vectors.wrappedKey,
    items: vectors.items
)

check("opens every login the web app wrote, and skips the rest", logins.count == vectors.expected.count)
for (got, want) in zip(logins, vectors.expected) {
    check(
        "\(want.id) decrypts exactly",
        got.id == want.id && got.name == want.name && got.username == want.username
            && got.password == want.password && got.url == want.url
    )
}

check("a subdomain matches", VaultMatch.matches(itemURL: "https://example.com", pageHost: "accounts.example.com"))
check("www is ignored", VaultMatch.matches(itemURL: "www.example.com", pageHost: "https://example.com/login"))
check("a lookalike does not match", !VaultMatch.matches(itemURL: "https://example.com", pageHost: "evil-example.com"))
check("a parent does not match", !VaultMatch.matches(itemURL: "https://accounts.example.com", pageHost: "example.com"))

exit(failures == 0 ? 0 : 1)
