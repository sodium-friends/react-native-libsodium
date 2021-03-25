require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name         = package['name']
  s.version      = package['version']
  s.summary      = package['description']
  s.license      = package['license']

  s.authors      = package['author']
  s.homepage     = package['homepage']
  s.platform     = :ios, "9.0"

  s.source       = { :git => "https://github.com/synonymdev/react-native-libsodium.git", :tag => "v#{s.version}" }
  s.source_files = ["ios/**/*.{h,m,mm,swift}"]

  s.vendored_frameworks = "libsodium/libsodium-apple/Clibsodium.xcframework"
  s.xcconfig = { 'HEADER_SEARCH_PATHS' => '${PODS_ROOT}/Headers/Public/#{s.name}/**'}

  s.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }

  s.dependency 'React-Core'
end
