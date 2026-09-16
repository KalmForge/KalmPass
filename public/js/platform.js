/**
 * Where the app is running.
 *
 * The same files are the website and, packaged by Capacitor, the iOS and
 * Android apps. Almost nothing needs to know the difference. What does:
 *
 *   - The apps are served from their own origin, so API calls go to
 *     kalmpass.net by full URL and carry a bearer token instead of the cookie.
 *   - Links to the website open in the system browser, not inside the app.
 *   - Files are handed to the share sheet, because a WebView cannot download.
 *   - Plans are not sold inside the apps. The stores require their own billing
 *     for that, so the apps show your plan and nothing to buy.
 *
 * On the website every check here is false and every helper does what the
 * browser would have done anyway.
 */

const capacitor = globalThis.Capacitor;

export const isNative = Boolean(capacitor?.isNativePlatform?.());

/** "ios", "android" or "web". */
export const platform = isNative ? capacitor.getPlatform() : "web";

/** Prefix for API calls. Empty on the website, where they are same-origin. */
export const API_ORIGIN = isNative ? "https://kalmpass.net" : "";

const SITE = "https://kalmpass.net";

/** Where "start again" goes: the app's own start page, or /app/ on the site. */
export const APP_HOME = isNative ? "/" : "/app/";

/** A Capacitor plugin by name, or null on the website. */
export const nativePlugin = (name) => (isNative ? (capacitor.Plugins?.[name] ?? null) : null);

/** Opens a page of the website, or any https address, outside the app. */
export async function openExternal(href) {
  const url = new URL(href, SITE).href;
  const browser = nativePlugin("Browser");
  if (browser) {
    await browser.open({ url });
  } else {
    window.open(url, "_blank", "noopener");
  }
}

/**
 * Files handed to the share sheet are written here first. The app it goes to
 * may read the file a while after the sheet closes, so the folder is emptied
 * before the next share and whenever the app starts, rather than at once.
 */
const SHARE_DIR = "share";

async function clearShared() {
  await nativePlugin("Filesystem")
    ?.rmdir({ path: SHARE_DIR, directory: "CACHE", recursive: true })
    .catch(() => {});
}

/**
 * Saves a file the person asked for: a download on the website, the share
 * sheet in the apps, where they can put it in Files, Drive or anywhere else.
 */
export async function saveFile(filename, content, type) {
  const files = nativePlugin("Filesystem");
  const share = nativePlugin("Share");
  if (files && share) {
    await clearShared();
    const { uri } = await files.writeFile({
      path: `${SHARE_DIR}/${filename}`,
      data: content,
      directory: "CACHE",
      encoding: "utf8",
      recursive: true,
    });
    try {
      await share.share({ title: filename, files: [uri] });
    } catch (error) {
      // Closing the share sheet is a choice, not a failure.
      if (!/cancel/i.test(error?.message ?? "")) throw error;
    }
    return;
  }

  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  // Revoked promptly so the blob, which may hold vault data, is not left alive.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * In the apps, a link to the website opens in the system browser. The one
 * exception is the logo, which on the site goes to the home page and in the
 * app has nowhere to go.
 */
function routeLinks() {
  document.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a[href]") : null;
    if (!link || link.hasAttribute("download")) return;

    const href = link.getAttribute("href");
    if (href === "/") {
      event.preventDefault();
      return;
    }
    if (href.startsWith("/") || href.startsWith("https://")) {
      event.preventDefault();
      openExternal(href);
    }
  });
}

if (isNative) {
  document.documentElement.dataset.platform = platform;
  routeLinks();
  clearShared();
}
