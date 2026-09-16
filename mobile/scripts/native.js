/**
 * Runs before the app, inside the iOS and Android apps only.
 *
 * Makes the native plugins reachable as Capacitor.Plugins.<name>, which is
 * where public/js/platform.js looks for them. The website never loads this.
 */
(() => {
  const cap = window.Capacitor;
  if (!cap?.isNativePlatform?.()) return;
  for (const name of ["KalmVault", "Browser", "Share", "Filesystem"]) {
    cap.Plugins[name] = cap.Plugins[name] ?? cap.registerPlugin(name);
  }
})();
