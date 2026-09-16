import AuthenticationServices
import Capacitor
import Foundation
import KalmVaultCore
import LocalAuthentication

/**
 * Unlocking the vault with Face ID or Touch ID, and the copy of the vault that
 * the AutoFill extension reads.
 *
 * The app hands this plugin a random 32-byte secret that the server knows as a
 * passkey. It goes into the Keychain behind biometrics, readable only on this
 * device and only while the same faces or fingers are enrolled. The web app
 * turns it back into the vault key; nothing here can open the vault on its own
 * and nothing here ever sees the master password.
 */
@objc(KalmVaultPlugin)
public class KalmVaultPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "KalmVaultPlugin"
    public let jsName = "KalmVault"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "status", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "enable", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "unlock", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "disable", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "saveVault", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "autofillStatus", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "openAutofillSettings", returnType: CAPPluginReturnPromise)
    ]

    private let store = SharedVaultStore()

    @objc func status(_ call: CAPPluginCall) {
        let context = LAContext()
        var error: NSError?
        var biometry = "none"
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            switch context.biometryType {
            case .faceID: biometry = "faceId"
            case .touchID: biometry = "touchId"
            default: biometry = "biometric"
            }
            if #available(iOS 17.0, *), context.biometryType == .opticID {
                biometry = "opticId"
            }
        }

        var result: [String: Any] = ["biometry": biometry, "enabled": false]
        if let meta = store.metadata() {
            result["enabled"] = true
            result["passkeyId"] = meta.passkeyId
        }
        call.resolve(result)
    }

    @objc func enable(_ call: CAPPluginCall) {
        guard
            let credentialId = call.getString("credentialId"),
            let passkeyId = call.getString("passkeyId"),
            let secret = call.getString("secret"),
            let wrappedKey = call.getString("wrappedKey")
        else {
            call.reject("Missing credential details.", "invalid")
            return
        }

        // Asked first, so turning this on is a deliberate act with the face or
        // finger that will later unlock the vault.
        let context = LAContext()
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Turn on unlocking KalmPass with biometrics"
        ) { success, error in
            guard success else {
                Self.rejectForAuthentication(call, error)
                return
            }
            do {
                try self.store.saveSecret(
                    UnlockSecret(credentialId: credentialId, secret: secret),
                    context: context
                )
                try self.store.saveMetadata(
                    UnlockMetadata(credentialId: credentialId, passkeyId: passkeyId, wrappedKey: wrappedKey)
                )
                call.resolve()
            } catch {
                self.store.clear()
                call.reject("Could not store the unlock key: \(error.localizedDescription)", "storage")
            }
        }
    }

    @objc func unlock(_ call: CAPPluginCall) {
        let reason = call.getString("reason") ?? "Unlock your vault"
        DispatchQueue.global(qos: .userInitiated).async {
            switch self.store.readSecret(reason: reason) {
            case .success(let unlock):
                call.resolve(["credentialId": unlock.credentialId, "secret": unlock.secret])
            case .failure(.cancelled):
                call.reject("Cancelled.", "cancelled")
            case .failure(.invalidated):
                // Biometrics changed since this was set up. The item can never
                // be read again, so it goes.
                self.store.clear()
                call.reject(
                    "Your phone's biometrics changed. Unlock with your master password and turn this on again.",
                    "invalidated"
                )
            case .failure(.other(let status)):
                call.reject("Could not read the unlock key (\(status)).", "storage")
            }
        }
    }

    @objc func disable(_ call: CAPPluginCall) {
        store.clear()
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities(nil)
        call.resolve()
    }

    /**
     * The vault as the server holds it, ciphertext only, for the AutoFill
     * extension. The site and username of each login also go to the system's
     * credential identity store, so iOS can suggest them above the keyboard.
     */
    @objc func saveVault(_ call: CAPPluginCall) {
        guard store.metadata() != nil else {
            call.resolve()
            return
        }

        let items: [VaultItem] = (call.getArray("items") ?? []).compactMap { entry in
            guard
                let row = entry as? [String: Any],
                let id = row["id"] as? String,
                let data = row["data"] as? String
            else { return nil }
            return VaultItem(id: id, data: data)
        }

        do {
            try store.saveItems(items)
        } catch {
            call.reject("Could not save the vault for AutoFill: \(error.localizedDescription)", "storage")
            return
        }

        let identities: [ASPasswordCredentialIdentity] = (call.getArray("identities") ?? []).compactMap { entry in
            guard
                let row = entry as? [String: Any],
                let id = row["id"] as? String,
                let url = row["url"] as? String,
                let username = row["username"] as? String,
                let host = VaultMatch.host(of: url)
            else { return nil }
            return ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: host, type: .domain),
                user: username,
                recordIdentifier: id
            )
        }

        ASCredentialIdentityStore.shared.getState { state in
            guard state.isEnabled else {
                call.resolve()
                return
            }
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(with: identities) { _, _ in
                call.resolve()
            }
        }
    }

    @objc func autofillStatus(_ call: CAPPluginCall) {
        ASCredentialIdentityStore.shared.getState { state in
            call.resolve(["supported": true, "enabled": state.isEnabled])
        }
    }

    /** iOS 17 can open the right page of Settings. Earlier versions cannot. */
    @objc func openAutofillSettings(_ call: CAPPluginCall) {
        if #available(iOS 17.0, *) {
            ASSettingsHelper.openCredentialProviderAppSettings { error in
                if let error {
                    call.reject(error.localizedDescription, "unavailable")
                } else {
                    call.resolve(["opened": true])
                }
            }
        } else {
            call.resolve(["opened": false])
        }
    }

    private static func rejectForAuthentication(_ call: CAPPluginCall, _ error: Error?) {
        let code = (error as? LAError)?.code
        let cancelled: [LAError.Code] = [.userCancel, .appCancel, .systemCancel, .userFallback]
        if let code, cancelled.contains(code) {
            call.reject("Cancelled.", "cancelled")
        } else {
            call.reject(error?.localizedDescription ?? "Biometrics are not available.", "unavailable")
        }
    }
}
