package net.kalmpass.vault;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * The few pieces of public/js/crypto.js that autofill needs, in Java.
 *
 * Decrypt only, from a passkey-style secret: HKDF for the encryption key,
 * AES-GCM to unwrap the vault key and open items, and the length prefix that
 * item padding adds. Formats are the web app's exactly.
 *
 * Plain Java at runtime, with no Android APIs, so the unit test can check it
 * against vectors made by the web code on an ordinary JVM.
 */
@androidx.annotation.RequiresApi(api = android.os.Build.VERSION_CODES.O)
final class VaultCrypto {

    /** Must match derivePasskeyKeys in crypto.js. */
    private static final String PASSKEY_LABEL = "kalmpass/v1/passkey";

    private VaultCrypto() {}

    static final class Login {

        final String id;
        final String name;
        final String username;
        final String password;
        final String url;

        Login(String id, String name, String username, String password, String url) {
            this.id = id;
            this.name = name;
            this.username = username;
            this.password = password;
            this.url = url;
        }

        String title() {
            if (!name.isEmpty()) return name;
            String host = hostOf(url);
            return host != null ? host : "Untitled";
        }
    }

    /**
     * HKDF-SHA256, one block, empty salt. WebCrypto treats an empty salt as an
     * empty HMAC key, which HMAC pads to the same zeros as this 32-byte key.
     * Java refuses a zero-length key, hence the explicit zeros.
     */
    static byte[] hkdf(byte[] secret, String info) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(secret);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info.getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 1);
        return mac.doFinal();
    }

    /** base64(iv || ciphertext || tag), as encryptBytes writes it. */
    static byte[] open(byte[] key, String blob) throws GeneralSecurityException {
        byte[] raw = Base64.getDecoder().decode(blob);
        if (raw.length < 12 + 16) throw new GeneralSecurityException("Ciphertext is too short.");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(128, Arrays.copyOfRange(raw, 0, 12))
        );
        return cipher.doFinal(raw, 12, raw.length - 12);
    }

    static byte[] unpad(byte[] padded) throws GeneralSecurityException {
        if (padded.length < 4) throw new GeneralSecurityException("Item is malformed.");
        int length = ByteBuffer.wrap(padded, 0, 4).getInt();
        if (length < 0 || length > padded.length - 4) throw new GeneralSecurityException("Item is malformed.");
        return Arrays.copyOfRange(padded, 4, 4 + length);
    }

    /** Opens every login it can. One unreadable item does not stop the rest. */
    static List<Login> decryptVault(String secretBase64, String wrappedKey, String itemsJson)
        throws GeneralSecurityException, JSONException {
        byte[] secret = Base64.getDecoder().decode(secretBase64);
        byte[] unwrapKey = hkdf(secret, PASSKEY_LABEL + "/enc");
        byte[] vaultKey = open(unwrapKey, wrappedKey);
        Arrays.fill(secret, (byte) 0);
        Arrays.fill(unwrapKey, (byte) 0);

        List<Login> logins = new ArrayList<>();
        JSONArray items = new JSONArray(itemsJson);
        for (int i = 0; i < items.length(); i++) {
            JSONObject row = items.getJSONObject(i);
            try {
                byte[] plain = unpad(open(vaultKey, row.getString("data")));
                JSONObject content = new JSONObject(new String(plain, StandardCharsets.UTF_8));
                String password = content.optString("password", "");
                if (password.isEmpty()) continue;
                logins.add(
                    new Login(
                        row.getString("id"),
                        content.optString("name", ""),
                        content.optString("username", ""),
                        password,
                        content.optString("url", "")
                    )
                );
            } catch (GeneralSecurityException | JSONException | IllegalArgumentException unreadable) {
                // Skipped, as the web app does.
            }
        }
        Arrays.fill(vaultKey, (byte) 0);
        return logins;
    }

    // --- matching --------------------------------------------------------------

    static String hostOf(String value) {
        if (value == null || value.isEmpty()) return null;
        String text = value.contains("://") ? value : "https://" + value;
        String host;
        try {
            host = new URI(text).getHost();
        } catch (java.net.URISyntaxException malformed) {
            return null;
        }
        if (host == null || host.isEmpty()) return null;
        host = host.toLowerCase(Locale.ROOT);
        return host.startsWith("www.") ? host.substring(4) : host;
    }

    /** Exact host, or a subdomain of the saved host. Never a bare substring. */
    static boolean matchesDomain(String itemUrl, String pageDomain) {
        String saved = hostOf(itemUrl);
        String page = hostOf(pageDomain);
        if (saved == null || page == null) return false;
        return page.equals(saved) || page.endsWith("." + saved);
    }

    /**
     * An app has a package name, not a web address, so this is a guess: the
     * site's name appearing as a part of the package, as github.com does in
     * com.github.android. Guesses are only used to sort the list, never to
     * fill without the person choosing.
     */
    static boolean matchesApp(String itemUrl, String packageName) {
        String host = hostOf(itemUrl);
        if (host == null || packageName == null) return false;
        List<String> parts = Arrays.asList(packageName.toLowerCase(Locale.ROOT).split("\\."));
        String[] labels = host.split("\\.");
        for (int i = 0; i < labels.length - 1; i++) {
            if (labels[i].length() >= 4 && parts.contains(labels[i])) return true;
        }
        return false;
    }
}
