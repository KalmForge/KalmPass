# Adds the AutoFill credential provider extension to the Xcode project.
#
# Capacitor generates the App target; this adds the second target beside it,
# which Capacitor has no notion of. It is idempotent, so CI runs it before
# every build, and on a Mac you can run it once and commit the result:
#
#   gem install xcodeproj   (already there if CocoaPods is)
#   ruby scripts/add-autofill-target.rb
#
# The extension compiles the shared storage and crypto files from the local
# plugin directly, so the app and the extension cannot disagree on formats.

require "xcodeproj"

project_path = File.expand_path("../ios/App/App.xcodeproj", __dir__)
project = Xcodeproj::Project.open(project_path)

if project.targets.any? { |target| target.name == "AutoFill" }
  puts "AutoFill target already present"
  exit 0
end

app = project.targets.find { |target| target.name == "App" }
abort "No App target in #{project_path}" unless app

extension = project.new_target(:app_extension, "AutoFill", :ios, "15.0", nil, :swift)

group = project.main_group.new_group("AutoFill", "AutoFill")
sources = [group.new_reference("CredentialProviderViewController.swift")]
group.new_reference("Info.plist")
group.new_reference("AutoFill.entitlements")

core = project.main_group.new_group("KalmVaultCore", "../../plugins/kalm-vault/ios/Sources/KalmVaultCore")
sources += %w[SharedVaultStore.swift VaultCrypto.swift].map { |name| core.new_reference(name) }

extension.add_file_references(sources)

app_settings = app.build_configurations.first.build_settings
extension.build_configurations.each do |config|
  settings = config.build_settings
  settings["PRODUCT_BUNDLE_IDENTIFIER"] = "net.kalmpass.app.autofill"
  settings["INFOPLIST_FILE"] = "AutoFill/Info.plist"
  settings["CODE_SIGN_ENTITLEMENTS"] = "AutoFill/AutoFill.entitlements"
  settings["GENERATE_INFOPLIST_FILE"] = "NO"
  settings["SWIFT_VERSION"] = "5.0"
  settings["TARGETED_DEVICE_FAMILY"] = "1,2"
  settings["IPHONEOS_DEPLOYMENT_TARGET"] = "15.0"
  settings["MARKETING_VERSION"] = app_settings["MARKETING_VERSION"] || "1.0"
  settings["CURRENT_PROJECT_VERSION"] = app_settings["CURRENT_PROJECT_VERSION"] || "1"
  settings["SKIP_INSTALL"] = "YES"
  settings["APPLICATION_EXTENSION_API_ONLY"] = "YES"
  settings["LD_RUNPATH_SEARCH_PATHS"] = [
    "$(inherited)",
    "@executable_path/Frameworks",
    "@executable_path/../../Frameworks",
  ]
end

app.build_configurations.each do |config|
  config.build_settings["CODE_SIGN_ENTITLEMENTS"] = "App/App.entitlements"
end
app_group = project.main_group.children.find { |child| child.display_name == "App" }
app_group&.new_reference("App.entitlements")

embed = app.new_copy_files_build_phase("Embed Foundation Extensions")
embed.symbol_dst_subfolder_spec = :plug_ins
embedded = embed.add_file_reference(extension.product_reference, true)
embedded.settings = { "ATTRIBUTES" => ["RemoveHeadersOnCopy"] }
app.add_dependency(extension)

project.save
puts "Added the AutoFill target to #{project_path}"
