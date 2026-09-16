package net.kalmpass.vault;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.app.assist.AssistStructure.ViewNode;
import android.content.Intent;
import android.os.Build;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.Dataset;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;
import android.text.InputType;
import android.view.View;
import android.view.ViewStructure.HtmlInfo;
import android.view.autofill.AutofillId;
import android.widget.RemoteViews;
import androidx.annotation.RequiresApi;
import java.util.List;
import java.util.Locale;

/**
 * KalmPass as Android's autofill service.
 *
 * When a login form appears, this offers one suggestion, "Fill with KalmPass".
 * It knows nothing about the vault at that point and never decrypts anything
 * here: choosing the suggestion opens AutofillUnlockActivity, which asks for a
 * fingerprint or face and only then opens the vault.
 */
@RequiresApi(api = Build.VERSION_CODES.O)
public class KalmAutofillService extends AutofillService {

    static final String EXTRA_WEB_DOMAIN = "net.kalmpass.vault.WEB_DOMAIN";
    static final String EXTRA_PACKAGE = "net.kalmpass.vault.PACKAGE";
    static final String EXTRA_USERNAME_ID = "net.kalmpass.vault.USERNAME_ID";
    static final String EXTRA_PASSWORD_ID = "net.kalmpass.vault.PASSWORD_ID";

    private static int requestCode = 0;

    /** The boxes that matter on a form, found by walking the view tree. */
    static final class Form {

        AutofillId username;
        AutofillId hintedUsername;
        AutofillId password;
        String webDomain;

        AutofillId bestUsername() {
            return hintedUsername != null ? hintedUsername : username;
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onFillRequest(FillRequest request, CancellationSignal cancellation, FillCallback callback) {
        List<FillContext> contexts = request.getFillContexts();
        AssistStructure structure = contexts.get(contexts.size() - 1).getStructure();
        String packageName = structure.getActivityComponent().getPackageName();

        // Never fill into KalmPass itself, and say nothing until it is set up.
        if (packageName.equals(getPackageName()) || !new UnlockStore(this).isEnabled()) {
            callback.onSuccess(null);
            return;
        }

        Form form = new Form();
        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            visit(structure.getWindowNodeAt(i).getRootViewNode(), form);
        }
        if (form.password == null) {
            callback.onSuccess(null);
            return;
        }

        AutofillId username = form.bestUsername();
        Intent intent = new Intent(this, AutofillUnlockActivity.class)
            .putExtra(EXTRA_WEB_DOMAIN, form.webDomain)
            .putExtra(EXTRA_PACKAGE, packageName)
            .putExtra(EXTRA_USERNAME_ID, username)
            .putExtra(EXTRA_PASSWORD_ID, form.password);

        int flags = PendingIntent.FLAG_CANCEL_CURRENT;
        // The system adds the form to this intent, so it has to stay mutable.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) flags |= PendingIntent.FLAG_MUTABLE;
        PendingIntent pending = PendingIntent.getActivity(this, ++requestCode, intent, flags);

        RemoteViews presentation = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
        presentation.setTextViewText(android.R.id.text1, "Fill with KalmPass");

        // A dataset whose values are unknown until the person authenticates.
        Dataset.Builder dataset = new Dataset.Builder(presentation);
        if (username != null) dataset.setValue(username, null);
        dataset.setValue(form.password, null);
        dataset.setAuthentication(pending.getIntentSender());

        callback.onSuccess(new FillResponse.Builder().addDataset(dataset.build()).build());
    }

    @Override
    public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        // Saving is done in the app, where the vault is open. No SaveInfo is
        // ever offered, so this is not normally called.
        callback.onSuccess();
    }

    // --- reading the form --------------------------------------------------------

    private static void visit(ViewNode node, Form form) {
        if (form.webDomain == null && node.getWebDomain() != null && !node.getWebDomain().isEmpty()) {
            form.webDomain = node.getWebDomain();
        }

        AutofillId id = node.getAutofillId();
        if (id != null && node.getAutofillType() == View.AUTOFILL_TYPE_TEXT) {
            if (isPassword(node)) {
                if (form.password == null) form.password = id;
            } else if (form.password == null) {
                if (hasHint(node, "username", "emailaddress", "email", "phone")) {
                    form.hintedUsername = id;
                } else if (looksLikeUsername(node)) {
                    // The last plausible text box before the password.
                    form.username = id;
                }
            }
        }

        for (int i = 0; i < node.getChildCount(); i++) {
            visit(node.getChildAt(i), form);
        }
    }

    private static boolean hasHint(ViewNode node, String... wanted) {
        String[] hints = node.getAutofillHints();
        if (hints == null) return false;
        for (String hint : hints) {
            String lower = hint.toLowerCase(Locale.ROOT);
            for (String candidate : wanted) {
                if (lower.contains(candidate)) return true;
            }
        }
        return false;
    }

    private static String htmlType(ViewNode node) {
        HtmlInfo html = node.getHtmlInfo();
        if (html == null || html.getAttributes() == null) return null;
        for (android.util.Pair<String, String> attribute : html.getAttributes()) {
            if ("type".equalsIgnoreCase(attribute.first)) return attribute.second.toLowerCase(Locale.ROOT);
        }
        return null;
    }

    private static boolean isPassword(ViewNode node) {
        if (hasHint(node, "password")) return true;
        if ("password".equals(htmlType(node))) return true;

        int type = node.getInputType();
        int kind = type & InputType.TYPE_MASK_CLASS;
        int variation = type & InputType.TYPE_MASK_VARIATION;
        if (kind == InputType.TYPE_CLASS_TEXT) {
            return (
                variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
            );
        }
        return kind == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD;
    }

    private static boolean looksLikeUsername(ViewNode node) {
        String html = htmlType(node);
        if (html != null) return html.equals("email") || html.equals("text") || html.equals("tel");

        int type = node.getInputType();
        if ((type & InputType.TYPE_MASK_CLASS) != InputType.TYPE_CLASS_TEXT) return false;
        int variation = type & InputType.TYPE_MASK_VARIATION;
        if (
            variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
        ) {
            return true;
        }

        String entry = node.getIdEntry();
        if (entry == null) return variation == InputType.TYPE_TEXT_VARIATION_NORMAL;
        String lower = entry.toLowerCase(Locale.ROOT);
        return lower.contains("user") || lower.contains("email") || lower.contains("login") || lower.contains("account");
    }
}
