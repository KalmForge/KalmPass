package net.kalmpass.vault;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import android.util.Base64;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Where the phone keeps what it needs to unlock the vault and to fill logins.
 *
 * The unlock secret is encrypted under an AES key that lives in the Android
 * Keystore, cannot leave it, and can only be used straight after a strong
 * biometric check. Enrolling a new fingerprint or face destroys the key, so the
 * secret cannot be read by whoever adds one. The ciphertext and the non-secret
 * details sit in private preferences, and the vault items, exactly as the
 * server holds them, in a private file for the autofill service.
 */
public final class UnlockStore {

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "kalmpass-unlock";
    private static final String PREFS = "kalmpass.unlock";
    private static final String ITEMS_FILE = "vault-items.json";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final Context context;

    public UnlockStore(Context context) {
        this.context = context.getApplicationContext();
    }

    private SharedPreferences prefs() {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public boolean isEnabled() {
        return prefs().contains("ciphertext");
    }

    public String passkeyId() {
        return prefs().getString("passkeyId", null);
    }

    public String wrappedKey() {
        return prefs().getString("wrappedKey", null);
    }

    // --- the key ---------------------------------------------------------------

    private SecretKey createKey() throws GeneralSecurityException {
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Zero seconds: every single use needs its own biometric check.
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            spec.setUnlockedDeviceRequired(true);
        }

        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(spec.build());
        return generator.generateKey();
    }

    private SecretKey loadKey() throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(KEYSTORE);
        store.load(null);
        SecretKey key = (SecretKey) store.getKey(KEY_ALIAS, null);
        if (key == null) throw new GeneralSecurityException("No unlock key on this phone.");
        return key;
    }

    /** A fresh key, and a cipher that becomes usable once the person authenticates. */
    public Cipher cipherForSaving() throws GeneralSecurityException, IOException {
        deleteKey();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, createKey());
        return cipher;
    }

    /**
     * Throws KeyPermanentlyInvalidatedException if biometrics changed since the
     * key was made. The caller should clear everything in that case.
     */
    public Cipher cipherForReading() throws GeneralSecurityException, IOException {
        String iv = prefs().getString("iv", null);
        if (iv == null) throw new GeneralSecurityException("Unlocking with this phone is not set up.");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, loadKey(), new GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)));
        return cipher;
    }

    private void deleteKey() {
        try {
            KeyStore store = KeyStore.getInstance(KEYSTORE);
            store.load(null);
            store.deleteEntry(KEY_ALIAS);
        } catch (GeneralSecurityException | IOException ignored) {
            // Nothing to delete.
        }
    }

    // --- the secret ------------------------------------------------------------

    public void save(Cipher authenticated, String credentialId, String passkeyId, String secret, String wrappedKey)
        throws GeneralSecurityException, JSONException {
        JSONObject payload = new JSONObject().put("credentialId", credentialId).put("secret", secret);
        byte[] ciphertext = authenticated.doFinal(payload.toString().getBytes(StandardCharsets.UTF_8));

        prefs()
            .edit()
            .putString("iv", Base64.encodeToString(authenticated.getIV(), Base64.NO_WRAP))
            .putString("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .putString("credentialId", credentialId)
            .putString("passkeyId", passkeyId)
            .putString("wrappedKey", wrappedKey)
            .commit();
    }

    /** Returns {credentialId, secret}. */
    public JSONObject open(Cipher authenticated) throws GeneralSecurityException, JSONException {
        String ciphertext = prefs().getString("ciphertext", null);
        if (ciphertext == null) throw new GeneralSecurityException("Unlocking with this phone is not set up.");
        byte[] plain = authenticated.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP));
        return new JSONObject(new String(plain, StandardCharsets.UTF_8));
    }

    // --- items for autofill ----------------------------------------------------

    private AtomicFile itemsFile() {
        return new AtomicFile(new java.io.File(context.getFilesDir(), ITEMS_FILE));
    }

    public void saveItems(String json) throws IOException {
        AtomicFile file = itemsFile();
        FileOutputStream out = file.startWrite();
        try {
            out.write(json.getBytes(StandardCharsets.UTF_8));
            file.finishWrite(out);
        } catch (IOException error) {
            file.failWrite(out);
            throw error;
        }
    }

    public String items() {
        try (FileInputStream in = itemsFile().openRead()) {
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = in.read(chunk)) != -1) buffer.write(chunk, 0, read);
            return buffer.toString("UTF-8");
        } catch (IOException missing) {
            return "[]";
        }
    }

    // --- everything ------------------------------------------------------------

    public void clear() {
        deleteKey();
        prefs().edit().clear().commit();
        itemsFile().delete();
    }
}
