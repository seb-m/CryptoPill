Pod::Spec.new do |s|

  s.name         = "CryptoPill"
  s.version      = "1.0.1"
  s.summary      = "CryptoPill is the crypto code used by Core Secret"
  s.homepage     = "https://github.com/seb-m/CryptoPill"
  s.license      = { :type => "MIT" }
  s.author       = { "Sébastien Martini" => "seb@dbzteam.org" }
  s.source       = { :git => "https://github.com/seb-m/CryptoPill.git", :tag => "1.0.1" }
  s.platform     = :ios, '7.0'
  s.dependency 'libsodium-ios'
  s.source_files = 'CryptoPill/**/*.{c,h,m}'
  s.requires_arc = true

end
