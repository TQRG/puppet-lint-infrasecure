Gem::Specification.new do |spec|
  spec.name = 'puppet-lint-security-iac'
  spec.version = '1.0.0'
  spec.author = 'Sofia Reis'
  spec.email = 'sofiareis1994@gmail.com'
  spec.homepage = 'https://github.com/TQRG/puppet-lint-security-iac'
  spec.license = 'MIT'
  spec.files = Dir[
    'README.md', 
    'lib/**/*',
    'spec/**/*'  
  ]
  
  spec.test_files  = Dir['spec/**/*']
  spec.summary = 'Puppet-lint plugins to check for security code smells in IaC.'
  spec.description = <<-EOF
    Checks puppet manifests for potential security issues.
  EOF

  spec.add_dependency             'puppet-lint', '~> 2.4', '>= 2.4.2'  
  spec.add_dependency             'dotenv', '~> 2.7', '>= 2.7.6'
  spec.add_dependency             'strong_password', '~> 0.0.10'
  spec.add_dependency  'json', '~> 2.6', '>= 2.6.1'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rspec-its', '~> 1.0'
  spec.add_development_dependency 'rspec-collection_matchers', '~> 1.0'
  spec.add_development_dependency 'rake', '~> 13.0', '>= 13.0.3'
  spec.add_development_dependency 'coveralls', '~> 0.7'
end