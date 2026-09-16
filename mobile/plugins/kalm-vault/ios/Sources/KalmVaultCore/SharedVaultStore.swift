import Foundation
import LocalAuthentication
import Security

/**
 * Storage shared by the app and its AutoFill extension.
 *
 * Three things are kept, each in the right place for what it is:
 *
 *   - The unlock secret, in the Keychain, behind biometrics, on this device
 *     only, and invalidated if the enrolled biometrics change.
 *   - Which passkey row the secret belongs to, and the vault key wrapped by it,
 *     in the shared app group's defaults. None of that opens anything alone.
 *   - The vault items, exactly as the server stores them, in a file in the app
 *     group container. Ciphertext, protected again by iOS file encryption.
 *
 * Compiled into the Capacitor plugin as a module and into the AutoFill
 * extension directly, so both read and write the same format.
 */

public struct UnlockSecret: Codable {
    public let credentialId: String
    public let secret: String

    public init(credentialId: String, secret: String) {
        self.credentialId = credentialId
        self.secret = secret
    }
}

public struct UnlockMetadata: Codable {
    public let credentialId: String
    public let passkeyId: String
    public let wrappedKey: String

    public init(credentialId: String, passkeyId: String, wrappedKey: String) {
        self.credentialId = credentialId
        self.passkeyId = passkeyId
        self.wrappedKey = wrappedKey
    }
}

public struct VaultItem: Codable {
    public let id: String
    public let data: String

    public init(id: String, data: String) {
        self.id = id
        self.data = data
    }
}

public enum SecretReadFailure: Error {
    case cancelled
    case invalidated
    case other(OSStatus)
}

public final class SharedVaultStore {
    private let service = "net.kalmpass.unlock"
    private let account = "vault-secret"
    private let metadataKey = "unlock"
    private let itemsFile = "vault-items.json"

    public init() {}

    /** From Info.plist, e.g. "ABCDE12345.net.kalmpass.shared". Absent in plain builds. */
    private var accessGroup: String? {
        nonEmpty(Bundle.main.object(forInfoDictionaryKey: "KalmKeychainGroup") as? String)
    }

    /** From Info.plist, e.g. "group.net.kalmpass". Absent in plain builds. */
    private var appGroup: String? {
        nonEmpty(Bundle.main.object(forInfoDictionaryKey: "KalmAppGroup") as? String)
    }

    private func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty, !value.contains("$(") else { return nil }
        return value
    }

    private var defaults: UserDefaults {
        appGroup.flatMap { UserDefaults(suiteName: $0) } ?? .standard
    }

    private var containerURL: URL {
        if let group = appGroup,
           let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) {
            return url
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }

    // MARK: secret

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }

    public func saveSecret(_ value: UnlockSecret, context: LAContext) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }

        SecItemDelete(baseQuery() as CFDictionary)

        var query = baseQuery()
        query[kSecValueData as String] = try JSONEncoder().encode(value)
        query[kSecAttrAccessControl as String] = access
        query[kSecUseAuthenticationContext as String] = context

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /** Blocks while the system asks for a face or fingerprint. Call off the main thread. */
    public func readSecret(reason: String) -> Result<UnlockSecret, SecretReadFailure> {
        let context = LAContext()
        context.localizedReason = reason

        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard
                let data = result as? Data,
                let value = try? JSONDecoder().decode(UnlockSecret.self, from: data)
            else { return .failure(.other(errSecDecode)) }
            return .success(value)
        case errSecUserCanceled:
            return .failure(.cancelled)
        case errSecItemNotFound, errSecAuthFailed:
            // With .biometryCurrentSet, a change of enrolled biometrics makes
            // the item unreadable for good.
            return .failure(.invalidated)
        default:
            return .failure(.other(status))
        }
    }

    // MARK: metadata

    public func saveMetadata(_ value: UnlockMetadata) throws {
        defaults.set(try JSONEncoder().encode(value), forKey: metadataKey)
    }

    public func metadata() -> UnlockMetadata? {
        guard let data = defaults.data(forKey: metadataKey) else { return nil }
        return try? JSONDecoder().decode(UnlockMetadata.self, from: data)
    }

    // MARK: items

    public func saveItems(_ items: [VaultItem]) throws {
        let data = try JSONEncoder().encode(items)
        try data.write(
            to: containerURL.appendingPathComponent(itemsFile),
            options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        )
    }

    public func items() -> [VaultItem] {
        guard let data = try? Data(contentsOf: containerURL.appendingPathComponent(itemsFile)) else {
            return []
        }
        return (try? JSONDecoder().decode([VaultItem].self, from: data)) ?? []
    }

    // MARK: everything

    public func clear() {
        SecItemDelete(baseQuery() as CFDictionary)
        defaults.removeObject(forKey: metadataKey)
        try? FileManager.default.removeItem(at: containerURL.appendingPathComponent(itemsFile))
    }
}
