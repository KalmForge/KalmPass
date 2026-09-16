package net.kalmpass.vault;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.service.autofill.Dataset;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;
import android.widget.Toast;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.crypto.Cipher;

/**
 * Opened when "Fill with KalmPass" is chosen on a form.
 *
 * Asks for a fingerprint or face, opens the vault in memory, lets the person
 * pick a login, and hands exactly that one back to the system. It then
 * finishes, and the decrypted list goes with it.
 */
@RequiresApi(api = Build.VERSION_CODES.O)
public class AutofillUnlockActivity extends AppCompatActivity {

    private AutofillId usernameId;
    private AutofillId passwordId;
    private String webDomain;
    private String packageName;

    @Override
    @SuppressWarnings("deprecation")
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        Intent intent = getIntent();
        usernameId = intent.getParcelableExtra(KalmAutofillService.EXTRA_USERNAME_ID);
        passwordId = intent.getParcelableExtra(KalmAutofillService.EXTRA_PASSWORD_ID);
        webDomain = intent.getStringExtra(KalmAutofillService.EXTRA_WEB_DOMAIN);
        packageName = intent.getStringExtra(KalmAutofillService.EXTRA_PACKAGE);

        if (passwordId == null) {
            giveUp(null);
            return;
        }

        UnlockStore store = new UnlockStore(this);
        Cipher cipher;
        try {
            cipher = store.cipherForReading();
        } catch (KeyPermanentlyInvalidatedException changed) {
            store.clear();
            giveUp("Your phone's biometrics changed. Open KalmPass and turn unlocking on again.");
            return;
        } catch (Exception error) {
            giveUp("Open KalmPass and turn on unlocking with this phone to fill passwords.");
            return;
        }

        String subtitle = webDomain != null ? "Fill a password for " + webDomain : "Fill a password";
        BiometricGate.ask(
            this,
            "KalmPass",
            subtitle,
            cipher,
            new BiometricGate.Callback() {
                @Override
                public void onSuccess(Cipher authenticated) {
                    try {
                        org.json.JSONObject unlock = store.open(authenticated);
                        List<VaultCrypto.Login> logins = VaultCrypto.decryptVault(
                            unlock.getString("secret"),
                            store.wrappedKey(),
                            store.items()
                        );
                        choose(logins);
                    } catch (Exception error) {
                        giveUp("KalmPass could not open the vault. Open the app to refresh it.");
                    }
                }

                @Override
                public void onCancel() {
                    giveUp(null);
                }

                @Override
                public void onError(String message) {
                    giveUp(message);
                }
            }
        );
    }

    private boolean fits(VaultCrypto.Login login) {
        return webDomain != null
            ? VaultCrypto.matchesDomain(login.url, webDomain)
            : VaultCrypto.matchesApp(login.url, packageName);
    }

    private void choose(List<VaultCrypto.Login> logins) {
        if (logins.isEmpty()) {
            giveUp("Your vault has no logins yet.");
            return;
        }

        List<VaultCrypto.Login> fitting = new ArrayList<>();
        for (VaultCrypto.Login login : logins) {
            if (fits(login)) fitting.add(login);
        }

        // A website is known exactly, so a single match is safe to fill. An
        // app's match is a guess, so the person always picks.
        if (webDomain != null && fitting.size() == 1) {
            fill(fitting.get(0));
            return;
        }

        showList(fitting.isEmpty() ? logins : fitting, fitting.isEmpty() ? null : logins);
    }

    private void showList(List<VaultCrypto.Login> shown, List<VaultCrypto.Login> everything) {
        List<VaultCrypto.Login> sorted = new ArrayList<>(shown);
        sorted.sort(Comparator.comparing((VaultCrypto.Login login) -> login.title().toLowerCase(java.util.Locale.ROOT)));

        String[] labels = new String[sorted.size()];
        for (int i = 0; i < sorted.size(); i++) {
            VaultCrypto.Login login = sorted.get(i);
            labels[i] = login.username.isEmpty() ? login.title() : login.title() + "\n" + login.username;
        }

        AlertDialog.Builder dialog = new AlertDialog.Builder(this)
            .setTitle(webDomain != null ? webDomain : "Choose a login")
            .setItems(labels, (d, which) -> fill(sorted.get(which)))
            .setOnCancelListener(d -> giveUp(null));

        if (everything != null && everything.size() > shown.size()) {
            dialog.setNeutralButton("Show all", (d, which) -> showList(everything, null));
        }
        dialog.show();
    }

    @SuppressWarnings("deprecation")
    private void fill(VaultCrypto.Login login) {
        RemoteViews presentation = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
        presentation.setTextViewText(android.R.id.text1, login.title());

        Dataset.Builder dataset = new Dataset.Builder(presentation);
        if (usernameId != null && !login.username.isEmpty()) {
            dataset.setValue(usernameId, AutofillValue.forText(login.username));
        }
        dataset.setValue(passwordId, AutofillValue.forText(login.password));

        Intent reply = new Intent();
        reply.putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build());
        setResult(RESULT_OK, reply);
        finish();
    }

    private void giveUp(String message) {
        if (message != null) Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        setResult(RESULT_CANCELED);
        finish();
    }
}
