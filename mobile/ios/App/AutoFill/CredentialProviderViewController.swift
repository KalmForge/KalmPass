import AuthenticationServices
import UIKit

/**
 * KalmPass in the iOS password AutoFill sheet.
 *
 * iOS runs this in its own process, outside the app. It reads the vault the app
 * left in the shared container (ciphertext only), asks for Face ID or Touch ID
 * to release the unlock secret from the shared Keychain, decrypts in memory,
 * and hands back the one login the person picks. Nothing decrypted is written
 * anywhere, and nothing here talks to the network.
 */
final class CredentialProviderViewController: ASCredentialProviderViewController,
    UITableViewDataSource, UITableViewDelegate, UISearchResultsUpdating
{
    private let store = SharedVaultStore()
    private var sites: [String] = []
    private var logins: [VaultLogin] = []
    private var shown: [VaultLogin] = []
    private var pendingRecord: String?

    private let table = UITableView(frame: .zero, style: .insetGrouped)
    private let search = UISearchController(searchResultsController: nil)
    private let message = UILabel()

    /**
     * The extension's root view has no navigation bar of its own, so the list
     * lives in a child navigation controller to get a Cancel button and search.
     */
    private let list = UIViewController()

    // MARK: requests from iOS

    /** The person tapped KalmPass in the AutoFill sheet. */
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        sites = serviceIdentifiers.map(\.identifier)
    }

    /** A suggestion above the keyboard was tapped. Always needs biometrics. */
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue
        ))
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        pendingRecord = credentialIdentity.recordIdentifier
    }

    // MARK: view

    override func viewDidLoad() {
        super.viewDidLoad()

        list.title = "KalmPass"
        list.view.backgroundColor = .systemGroupedBackground
        list.navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel, target: self, action: #selector(cancel)
        )

        search.searchResultsUpdater = self
        search.obscuresBackgroundDuringPresentation = false
        search.searchBar.placeholder = "Search logins"
        list.navigationItem.searchController = search
        list.navigationItem.hidesSearchBarWhenScrolling = false

        let navigation = UINavigationController(rootViewController: list)
        addChild(navigation)
        navigation.view.frame = view.bounds
        navigation.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(navigation.view)
        navigation.didMove(toParent: self)

        let view = list.view!

        table.dataSource = self
        table.delegate = self
        table.register(UITableViewCell.self, forCellReuseIdentifier: "login")
        table.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(table)

        message.numberOfLines = 0
        message.textAlignment = .center
        message.textColor = .secondaryLabel
        message.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(message)

        NSLayoutConstraint.activate([
            table.topAnchor.constraint(equalTo: view.topAnchor),
            table.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            table.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            table.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            message.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            message.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
            message.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor)
        ])
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if logins.isEmpty { unlock() }
    }

    // MARK: unlocking

    private func unlock() {
        guard let meta = store.metadata() else {
            show("Open KalmPass and turn on unlocking with this phone to use AutoFill.")
            return
        }
        show("Unlocking...")

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.store.readSecret(reason: "Fill a password from KalmPass")
            DispatchQueue.main.async {
                switch result {
                case .success(let unlock):
                    self.open(secret: unlock.secret, meta: meta)
                case .failure(.cancelled):
                    self.cancel()
                case .failure(.invalidated):
                    self.show("Your phone's biometrics changed. Open KalmPass and turn unlocking on again.")
                case .failure(.other):
                    self.show("KalmPass could not unlock. Open the app and try again.")
                }
            }
        }
    }

    private func open(secret: String, meta: UnlockMetadata) {
        do {
            logins = try VaultCrypto.decryptVault(
                secretBase64: secret,
                wrappedKey: meta.wrappedKey,
                items: store.items()
            )
        } catch {
            show("KalmPass could not open the vault. Open the app to refresh it.")
            return
        }

        if let record = pendingRecord {
            if let login = logins.first(where: { $0.id == record }) {
                complete(with: login)
            } else {
                show("That login is no longer in your vault.")
            }
            return
        }

        filter(query: "")
        if logins.isEmpty {
            show("Your vault has no logins yet.")
        }
    }

    // MARK: list

    private func matchesSite(_ login: VaultLogin) -> Bool {
        sites.contains { VaultMatch.matches(itemURL: login.url, pageHost: $0) }
    }

    private func filter(query: String) {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        let found = logins.filter { login in
            needle.isEmpty
                || login.title.lowercased().contains(needle)
                || login.username.lowercased().contains(needle)
                || login.url.lowercased().contains(needle)
        }
        // Logins for the site being filled first, then everything else by name.
        shown = found.sorted { a, b in
            let aHere = matchesSite(a), bHere = matchesSite(b)
            if aHere != bHere { return aHere }
            return a.title.localizedCaseInsensitiveCompare(b.title) == .orderedAscending
        }
        message.isHidden = true
        table.isHidden = false
        table.reloadData()
    }

    func updateSearchResults(for searchController: UISearchController) {
        guard !logins.isEmpty else { return }
        filter(query: searchController.searchBar.text ?? "")
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        shown.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let login = shown[indexPath.row]
        let cell = tableView.dequeueReusableCell(withIdentifier: "login", for: indexPath)
        var content = cell.defaultContentConfiguration()
        content.text = login.title
        content.secondaryText = [login.username, VaultMatch.host(of: login.url) ?? ""]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
        content.image = UIImage(systemName: matchesSite(login) ? "key.fill" : "key")
        cell.contentConfiguration = content
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        complete(with: shown[indexPath.row])
    }

    // MARK: finishing

    private func complete(with login: VaultLogin) {
        extensionContext.completeRequest(
            withSelectedCredential: ASPasswordCredential(user: login.username, password: login.password),
            completionHandler: nil
        )
        logins = []
        shown = []
    }

    @objc private func cancel() {
        logins = []
        shown = []
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userCanceled.rawValue
        ))
    }

    private func show(_ text: String) {
        message.text = text
        message.isHidden = false
        table.isHidden = true
    }
}
