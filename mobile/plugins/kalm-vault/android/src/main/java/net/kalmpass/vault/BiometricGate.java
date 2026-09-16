package net.kalmpass.vault;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import javax.crypto.Cipher;

/**
 * The system biometric prompt, bound to a Keystore cipher.
 *
 * Binding matters: the cipher only works after this particular prompt
 * succeeds, so a compromised app process cannot skip the prompt and use the
 * key anyway.
 */
final class BiometricGate {

    interface Callback {
        void onSuccess(Cipher cipher);

        void onCancel();

        void onError(String message);
    }

    private BiometricGate() {}

    static boolean available(android.content.Context context) {
        return BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS;
    }

    static void ask(FragmentActivity activity, String title, String subtitle, Cipher cipher, Callback callback) {
        activity.runOnUiThread(() -> {
            BiometricPrompt prompt = new BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
                        if (crypto == null || crypto.getCipher() == null) {
                            callback.onError("The biometric check did not unlock the key.");
                        } else {
                            callback.onSuccess(crypto.getCipher());
                        }
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence message) {
                        if (
                            code == BiometricPrompt.ERROR_USER_CANCELED ||
                            code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                            code == BiometricPrompt.ERROR_CANCELED
                        ) {
                            callback.onCancel();
                        } else {
                            callback.onError(message.toString());
                        }
                    }
                }
            );

            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();

            prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
        });
    }
}
