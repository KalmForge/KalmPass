package net.kalmpass.vault;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

/**
 * Checks the Java port against ciphertext made by public/js/crypto.js.
 * The vectors come from scripts/make-vectors.mjs.
 */
public class VaultCryptoTest {

    private static JSONObject vectors() throws Exception {
        // Gradle runs unit tests from the module directory.
        byte[] raw = Files.readAllBytes(Paths.get("..", "test-vectors.json"));
        return new JSONObject(new String(raw, StandardCharsets.UTF_8));
    }

    @Test
    public void opensWhatTheWebAppWrote() throws Exception {
        JSONObject v = vectors();
        List<VaultCrypto.Login> logins = VaultCrypto.decryptVault(
            v.getString("secret"),
            v.getString("wrappedKey"),
            v.getJSONArray("items").toString()
        );

        JSONArray expected = v.getJSONArray("expected");
        assertEquals(expected.length(), logins.size());
        for (int i = 0; i < expected.length(); i++) {
            JSONObject want = expected.getJSONObject(i);
            VaultCrypto.Login got = logins.get(i);
            assertEquals(want.getString("id"), got.id);
            assertEquals(want.getString("name"), got.name);
            assertEquals(want.getString("username"), got.username);
            assertEquals(want.getString("password"), got.password);
            assertEquals(want.getString("url"), got.url);
        }
    }

    @Test
    public void matchesSitesTheWayTheExtensionDoes() {
        assertTrue(VaultCrypto.matchesDomain("https://example.com", "accounts.example.com"));
        assertTrue(VaultCrypto.matchesDomain("www.example.com", "example.com"));
        assertFalse(VaultCrypto.matchesDomain("https://example.com", "evil-example.com"));
        assertFalse(VaultCrypto.matchesDomain("https://accounts.example.com", "example.com"));
        assertTrue(VaultCrypto.matchesApp("https://github.com", "com.github.android"));
        assertFalse(VaultCrypto.matchesApp("https://github.com", "com.example.git"));
    }
}
