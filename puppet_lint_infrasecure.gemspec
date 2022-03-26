lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'puppet-lint-infrasecure/version'


Gem::Specification.new do |spec|
  spec.name = 'puppet-lint-infrasecure'
  spec.version = InfraSecure::VERSION
  spec.author = 'Sofia Reis'
  spec.email = 'sofiareis1994@gmail.com'
  spec.homepage = 'https://github.com/TQRG/puppet-lint-infrasecure'
  spec.license = 'MIT'
  spec.files = Dir[
    'README.md', 
    'lib/**/*',
    'spec/**/*'  
  ]
  spec.metadata    = { "source_code_uri" => spec.homepage }

  spec.test_files  = Dir['spec/**/*']
  spec.summary = 'Puppet-lint plugins to detect security code smells in puppet scripts.'
  spec.description = <<-EOF
    Checks puppet manifests for potential security issues: admin_by_default,
    cyrillic_homograph_attack, empty_password, hardcoded_secret, invalid_ip_addr_binding,
    malicious_dependency, suspicious_comment, use_http_without_tls, use_of_weak_crypto_algorithm
    and weak_password.
  EOF

  spec.required_ruby_version = '>= 3.0.3'

  spec.add_dependency             'puppet-lint', '~> 2.4', '>= 2.4.2'  
  spec.add_dependency             'dotenv', '~> 2.7', '>= 2.7.6'
  spec.add_dependency             'strong_password', '~> 0.0.10'
  spec.add_dependency             'json', '~> 2.6', '>= 2.6.1'
  spec.add_dependency             'yaml', '~> 0.2.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rspec-its', '~> 1.0'
  spec.add_development_dependency 'rspec-collection_matchers', '~> 1.0'
  spec.add_development_dependency 'rake', '~> 13.0', '>= 13.0.3'
  spec.add_development_dependency 'coveralls', '~> 0.7'
end