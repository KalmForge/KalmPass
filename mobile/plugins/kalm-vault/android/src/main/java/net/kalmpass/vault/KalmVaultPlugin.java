package net.kalmpass.vault;

import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.view.autofill.AutofillManager;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import javax.crypto.Cipher;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Unlocking the vault with a fingerprint or face, and the copy of the vault
 * the autofill service reads.
 *
 * The app hands this plugin a random 32-byte secret that the server knows as a
 * passkey. It is kept encrypted under a Keystore key that needs a strong
 * biometric check for every use. Nothing here can open the vault by itself,
 * and nothing here ever sees the master password.
 */
@CapacitorPlugin(name = "KalmVault")
public class KalmVaultPlugin extends Plugin {

    private UnlockStore store() {
        return new UnlockStore(getContext());
    }

    @PluginMethod
    public void status(PluginCall call) {
        UnlockStore store = store();
        JSObject result = new JSObject();
        result.put("biometry", BiometricGate.available(getContext()) ? "biometric" : "none");
        result.put("enabled", store.isEnabled());
        if (store.isEnabled()) result.put("passkeyId", store.passkeyId());
        call.resolve(result);
    }

    @PluginMethod
    public void enable(PluginCall call) {
        String credentialId = call.getString("credentialId");
        String passkeyId = call.getString("passkeyId");
        String secret = call.getString("secret");
        String wrappedKey = call.getString("wrappedKey");
        if (credentialId == null || passkeyId == null || secret == null || wrappedKey == null) {
            call.reject("Missing credential details.", "invalid");
            return;
        }

        UnlockStore store = store();
        Cipher cipher;
        try {
            cipher = store.cipherForSaving();
        } catch (Exception error) {
            store.clear();
            call.reject("This phone cannot hold an unlock key: " + error.getMessage(), "unavailable");
            return;
        }

        BiometricGate.ask(
            getActivity(),
            "Unlock KalmPass with biometrics",
            "Confirm it is you to turn this on",
            cipher,
            new BiometricGate.Callback() {
                @Override
                public void onSuccess(Cipher authenticated) {
                    try {
                        store.save(authenticated, credentialId, passkeyId, secret, wrappedKey);
                        call.resolve();
                    } catch (Exception error) {
                        store.clear();
                        call.reject("Could not store the unlock key: " + error.getMessage(), "storage");
                    }
                }

                @Override
                public void onCancel() {
                    store.clear();
                    call.reject("Cancelled.", "cancelled");
                }

                @Override
                public void onError(String message) {
                    store.clear();
                    call.reject(message, "unavailable");
                }
            }
        );
    }

    @PluginMethod
    public void unlock(PluginCall call) {
        UnlockStore store = store();
        Cipher cipher;
        try {
            cipher = store.cipherForReading();
        } catch (KeyPermanentlyInvalidatedException changed) {
            // New biometrics were enrolled. The key is gone for good.
            store.clear();
            call.reject(
                "Your phone's biometrics changed. Unlock with your master password and turn this on again.",
                "invalidated"
            );
            return;
        } catch (Exception error) {
            call.reject("Could not read the unlock key: " + error.getMessage(), "storage");
            return;
        }

        String reason = call.getString("reason", "Unlock your vault");
        BiometricGate.ask(
            getActivity(),
            "KalmPass",
            reason,
            cipher,
            new BiometricGate.Callback() {
                @Override
                public void onSuccess(Cipher authenticated) {
                    try {
                        JSONObject unlock = store.open(authenticated);
                        JSObject result = new JSObject();
                        result.put("credentialId", unlock.getString("credentialId"));
                        result.put("secret", unlock.getString("secret"));
                        call.resolve(result);
                    } catch (Exception error) {
                        call.reject("Could not read the unlock key: " + error.getMessage(), "storage");
                    }
                }

                @Override
                public void onCancel() {
                    call.reject("Cancelled.", "cancelled");
                }

                @Override
                public void onError(String message) {
                    call.reject(message, "unavailable");
                }
            }
        );
    }

    @PluginMethod
    public void disable(PluginCall call) {
        store().clear();
        call.resolve();
    }

    /** Ciphertext only, as the server holds it, for the autofill service. */
    @PluginMethod
    public void saveVault(PluginCall call) {
        UnlockStore store = store();
        if (!store.isEnabled()) {
            call.resolve();
            return;
        }
        try {
            JSArray items = call.getArray("items", new JSArray());
            JSONArray rows = new JSONArray();
            for (int i = 0; i < items.length(); i++) {
                JSONObject item = items.getJSONObject(i);
                rows.put(new JSONObject().put("id", item.getString("id")).put("data", item.getString("data")));
            }
            store.saveItems(rows.toString());
            call.resolve();
        } catch (Exception error) {
            call.reject("Could not save the vault for autofill: " + error.getMessage(), "storage");
        }
    }

    @PluginMethod
    public void autofillStatus(PluginCall call) {
        JSObject result = new JSObject();
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            result.put("supported", false);
            result.put("enabled", false);
        } else {
            AutofillManager manager = getContext().getSystemService(AutofillManager.class);
            result.put("supported", manager != null && manager.isAutofillSupported());
            result.put("enabled", manager != null && manager.hasEnabledAutofillServices());
        }
        call.resolve(result);
    }

    @PluginMethod
    public void openAutofillSettings(PluginCall call) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            call.resolve(new JSObject().put("opened", false));
            return;
        }
        Intent intent = new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE);
        intent.setData(Uri.parse("package:" + getContext().getPackageName()));
        try {
            getActivity().startActivity(intent);
            call.resolve(new JSObject().put("opened", true));
        } catch (Exception error) {
            call.resolve(new JSObject().put("opened", false));
        }
    }
}
