require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-libsodium"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "10.0" }
  s.source       = { :git => "https://www.github.com/hyperdivsion/react-native-libsodium.git", :tag => "#{s.version}" }

  
  s.source_files = ["ios/**/*.{h,m,mm,swift}","libsodium/libsodium-ios/**/*.{h,m}"]
  
  s.vendored_libraries = 'libsodium/libsodium-ios/lib/libsodium.a'
  s.xcconfig = { 'HEADER_SEARCH_PATHS' => ['${PODS_ROOT}/Headers/Public/#{s.name}/**', 'libsodium/libsodium-ios/**/*.{h,m}']}

  s.dependency "React-Core"
end
