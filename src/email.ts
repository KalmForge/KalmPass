/**
 * Transactional email.
 *
 * Three rules hold for everything sent from here:
 *
 *   - No link ever signs anyone in. A verification or reset link proves control
 *     of the mailbox and nothing more; it cannot be used to reach a vault,
 *     because reaching a vault needs a master password we do not have.
 *   - No vault content, ever. Not item names, not counts, not hostnames.
 *   - Delivery failure is never fatal. If the domain is not onboarded yet the
 *     send is logged and the caller continues; an account is still usable while
 *     unverified, and the mail can be retried.
 */

const BRAND = {
  navy: "#0b2a6b",
  deep: "#061634",
  accent: "#2b8ce6",
  teal: "#2fd8bc",
  text: "#1b2430",
  dim: "#5b6674",
  line: "#dde3ec",
};

interface Mail {
  subject: string;
  heading: string;
  /** Plain paragraphs. Kept prose-only so the text part reads naturally too. */
  lines: string[];
  action?: { label: string; url: string };
  footnote?: string;
}

/**
 * Email clients strip <style> blocks and block remote images, so the mark is
 * drawn with nested tables and background colours, it renders the same
 * everywhere, including in a plain dark-mode inbox.
 */
function layout(mail: Mail): string {
  const button = mail.action
    ? `
      <tr><td style="padding:8px 0 4px">
        <a href="${escape(mail.action.url)}"
           style="display:inline-block;background:${BRAND.accent};color:#ffffff;text-decoration:none;
                  font-weight:600;font-size:15px;padding:13px 26px;border-radius:9px">
          ${escape(mail.action.label)}
        </a>
      </td></tr>
      <tr><td style="padding:14px 0 0;font-size:13px;color:${BRAND.dim};line-height:1.6">
        If the button does not work, copy this into your browser:<br>
        <span style="color:${BRAND.accent};word-break:break-all">${escape(mail.action.url)}</span>
      </td></tr>`
    : "";

  const body = mail.lines
    .map(
      (line) =>
        `<tr><td style="padding:0 0 14px;font-size:15px;line-height:1.65;color:${BRAND.text}">${escape(line)}</td></tr>`,
    )
    .join("");

  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#eef1f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f6;padding:28px 12px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="max-width:520px;background:#ffffff;border-radius:14px;overflow:hidden;
                    border:1px solid ${BRAND.line}">

        <tr><td style="background:${BRAND.navy};padding:20px 28px">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="width:30px;height:30px;background:${BRAND.teal};border-radius:9px;
                       text-align:center;vertical-align:middle;color:${BRAND.deep};
                       font-size:17px;font-weight:800;line-height:30px">K</td>
            <td style="padding-left:11px;color:#ffffff;font-size:17px;font-weight:650;
                       letter-spacing:-.2px">KalmPass</td>
          </tr></table>
        </td></tr>

        <tr><td style="padding:28px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="padding:0 0 14px;font-size:20px;font-weight:650;color:${BRAND.text};
                           letter-spacing:-.3px">${escape(mail.heading)}</td></tr>
            ${body}
            ${button}
          </table>
        </td></tr>

        <tr><td style="padding:18px 28px 24px;border-top:1px solid ${BRAND.line};
                       font-size:12.5px;line-height:1.6;color:${BRAND.dim}">
          ${escape(mail.footnote ?? "")}
          ${mail.footnote ? "<br><br>" : ""}
          KalmPass cannot read your vault and cannot reset your master password.
          Nobody from KalmPass will ever ask you for it.
        </td></tr>

      </table>
    </td></tr>
  </table>
</body></html>`;
}

function plain(mail: Mail): string {
  return [
    `KalmPass. ${mail.heading}`,
    "",
    ...mail.lines,
    mail.action ? `\n${mail.action.label}:\n${mail.action.url}` : "",
    "",
    mail.footnote ?? "",
    "",
    "KalmPass cannot read your vault and cannot reset your master password.",
    "Nobody from KalmPass will ever ask you for it.",
  ]
    .filter((line) => line !== "")
    .join("\n");
}

const escape = (value: string) =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

/** Returns whether it actually went out, so callers can tell the user the truth. */
async function send(env: Env, to: string, mail: Mail): Promise<boolean> {
  if (!env.EMAIL) {
    console.warn(`email skipped (no EMAIL binding): "${mail.subject}" to ${to}`);
    return false;
  }
  try {
    await env.EMAIL.send({
      to,
      from: { email: env.MAIL_FROM, name: env.MAIL_FROM_NAME || "KalmPass" },
      subject: mail.subject,
      html: layout(mail),
      text: plain(mail),
    });
    return true;
  } catch (error) {
    // A bounced verification must not take the signup down with it.
    console.error("email send failed", error);
    return false;
  }
}

// --- the messages -----------------------------------------------------------

export const sendVerification = (env: Env, to: string, url: string) =>
  send(env, to, {
    subject: "Confirm your KalmPass email",
    heading: "Confirm your email address",
    lines: [
      "Your vault is already set up and ready to use. Confirming your address keeps it active and lets us reach you if there is ever a security issue.",
      "This link is good for 24 hours.",
    ],
    action: { label: "Confirm my email", url },
    footnote: "If you did not create a KalmPass account, you can ignore this message.",
  });

export const sendAccountReset = (env: Env, to: string, url: string) =>
  send(env, to, {
    subject: "Erase your KalmPass vault",
    heading: "You asked to erase your vault",
    lines: [
      "This is the last resort for an account whose master password and Recovery Key are both lost. Because we hold no key to your data, there is no way to recover it. The only thing we can do is clear the account so you can start again.",
      "Continuing will permanently destroy every item in your vault. Anything you have not exported is gone.",
      "If you still have your Recovery Key, stop here and use that instead. It restores your vault intact.",
      "This link is good for one hour and can be used once.",
    ],
    action: { label: "Erase my vault and start over", url },
    footnote: "If you did not request this, ignore it and nothing will happen.",
  });

export const sendRecoveryUsed = (env: Env, to: string, when: string) =>
  send(env, to, {
    subject: "Your KalmPass Recovery Key was used",
    heading: "Your Recovery Key was used",
    lines: [
      `Someone used your Recovery Key to set a new master password on ${when}.`,
      "If that was you, nothing further is needed. A fresh Recovery Key was issued at the same time and the old one no longer works.",
      "If it was not you, whoever did it now has access to your vault. Change your master password immediately and review your recent activity.",
    ],
    action: { label: "Review account activity", url: `${env.APP_URL}/app/` },
  });

export const sendPasswordChanged = (env: Env, to: string, when: string) =>
  send(env, to, {
    subject: "Your KalmPass master password was changed",
    heading: "Your master password was changed",
    lines: [
      `The master password on your account was changed on ${when}, and every other signed-in device was signed out.`,
      "If this was not you, use your Recovery Key to take the account back straight away.",
    ],
    action: { label: "Open KalmPass", url: `${env.APP_URL}/app/` },
  });

export const sendEmailChanged = (env: Env, to: string, next: string, when: string) =>
  send(env, to, {
    subject: "Your KalmPass email address was changed",
    heading: "Your email address was changed",
    lines: [
      `On ${when} the address on your account was changed to ${next}. Signing in now uses the new address.`,
      "If that was you, nothing further is needed. A fresh Recovery Key was issued at the same time, because your old one no longer opens the vault.",
      "If it was not you, somebody with your master password has taken the account. Use your Recovery Key immediately to set a new password and take it back.",
    ],
    action: { label: "Open KalmPass", url: `${env.APP_URL}/app/` },
    footnote: "This message went to the previous address on the account, so that a change you did not make cannot happen quietly.",
  });

export const sendNewDeviceAlert = (env: Env, to: string, device: string, when: string) =>
  send(env, to, {
    subject: "New sign-in to your KalmPass vault",
    heading: "A new device signed in",
    lines: [
      `${device} signed in to your vault on ${when}.`,
      "If that was you, there is nothing to do.",
      "If it was not, change your master password now. Whoever signed in has the current one.",
    ],
    action: { label: "Review account activity", url: `${env.APP_URL}/app/` },
  });
