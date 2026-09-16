import CryptoKit
import Foundation

/**
 * The few pieces of public/js/crypto.js that AutoFill needs, in Swift.
 *
 * It only ever decrypts, and only from a passkey-style secret, so this is the
 * whole of it: HKDF to get the encryption key, AES-GCM to unwrap the vault key
 * and open items, and the length prefix that item padding adds. The formats
 * are the web app's exactly: base64(iv || ciphertext || tag), a 12-byte IV and
 * a 16-byte tag, and a big-endian length before the JSON.
 */
public enum VaultCrypto {
    public enum Failure: Error {
        case malformed
    }

    /** The label must match derivePasskeyKeys in crypto.js. */
    static let passkeyLabel = "kalmpass/v1/passkey"

    /**
     * HKDF-SHA256 with an empty salt, as WebCrypto does it. An empty HMAC key
     * and a key of zeros give the same result, so this matches byte for byte.
     */
    static func encryptionKey(fromSecret secret: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            salt: Data(),
            info: Data("\(passkeyLabel)/enc".utf8),
            outputByteCount: 32
        )
    }

    static func open(_ blob: String, with key: SymmetricKey) throws -> Data {
        guard let raw = Data(base64Encoded: blob), raw.count >= 12 + 16 else {
            throw Failure.malformed
        }
        let bytes = [UInt8](raw)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Data(bytes[0..<12])),
            ciphertext: Data(bytes[12..<(bytes.count - 16)]),
            tag: Data(bytes[(bytes.count - 16)...])
        )
        return try AES.GCM.open(box, using: key)
    }

    static func unpad(_ data: Data) throws -> Data {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else { throw Failure.malformed }
        let length = Int(bytes[0]) << 24 | Int(bytes[1]) << 16 | Int(bytes[2]) << 8 | Int(bytes[3])
        guard length <= bytes.count - 4 else { throw Failure.malformed }
        return Data(bytes[4..<(4 + length)])
    }

    /** Opens every item it can. One unreadable item does not stop the rest. */
    public static func decryptVault(
        secretBase64: String,
        wrappedKey: String,
        items: [VaultItem]
    ) throws -> [VaultLogin] {
        guard let secret = Data(base64Encoded: secretBase64) else { throw Failure.malformed }
        let unwrapKey = encryptionKey(fromSecret: secret)
        let vaultKey = SymmetricKey(data: try open(wrappedKey, with: unwrapKey))

        return items.compactMap { item in
            guard
                let plain = try? unpad(open(item.data, with: vaultKey)),
                let content = try? JSONSerialization.jsonObject(with: plain) as? [String: Any],
                let password = content["password"] as? String,
                !password.isEmpty
            else { return nil }

            return VaultLogin(
                id: item.id,
                name: content["name"] as? String ?? "",
                username: content["username"] as? String ?? "",
                password: password,
                url: content["url"] as? String ?? ""
            )
        }
    }
}

public struct VaultLogin {
    public let id: String
    public let name: String
    public let username: String
    public let password: String
    public let url: String

    public var title: String {
        if !name.isEmpty { return name }
        return VaultMatch.host(of: url) ?? "Untitled"
    }
}

/** The same site matching as the browser extension's. */
public enum VaultMatch {
    public static func host(of value: String) -> String? {
        let text = value.contains("://") ? value : "https://\(value)"
        guard let host = URL(string: text)?.host?.lowercased(), !host.isEmpty else { return nil }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    /** Exact host, or a subdomain of the saved host. Never a bare substring. */
    public static func matches(itemURL: String, pageHost: String) -> Bool {
        guard let saved = host(of: itemURL), let page = host(of: pageHost) else { return false }
        return page == saved || page.hasSuffix(".\(saved)")
    }
}
