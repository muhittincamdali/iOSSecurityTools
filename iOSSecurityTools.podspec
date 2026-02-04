Pod::Spec.new do |s|
  s.name             = 'iOSSecurityTools'
  s.version          = '1.0.0'
  s.summary          = 'Security utilities for iOS with encryption and keychain helpers.'
  s.description      = <<-DESC
    iOSSecurityTools provides comprehensive security utilities for iOS applications.
    Features include AES/RSA encryption, secure keychain storage, biometric authentication,
    certificate pinning, jailbreak detection, and security best practices.
  DESC

  s.homepage         = 'https://github.com/muhittincamdali/iOSSecurityTools'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Muhittin Camdali' => 'contact@muhittincamdali.com' }
  s.source           = { :git => 'https://github.com/muhittincamdali/iOSSecurityTools.git', :tag => s.version.to_s }

  s.ios.deployment_target = '15.0'
  s.osx.deployment_target = '12.0'

  s.swift_versions = ['5.9', '5.10', '6.0']
  s.source_files = 'Sources/**/*.swift'
  s.frameworks = 'Foundation', 'Security', 'LocalAuthentication', 'CryptoKit'
end
