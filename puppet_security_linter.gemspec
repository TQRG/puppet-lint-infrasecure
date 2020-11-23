Gem::Specification.new do |s|
  s.name = 'puppet-security-linter'
  s.version = "0.0.0"
  s.authors = ["Sofia Reis", "Rui Abreu"]
  s.summary = 'Security Linter for Puppet'
  s.homepage = 'https://github.com/TQRG/puppet-security-linter'
  s.platform = Gem::Platform::RUBY
  s.required_ruby_version = '>= 2.5.0'
  s.license = 'MIT'
  s.files = Dir[
    'README.md', 
    'puppet_sec_linter.gemspec', 
    'lib/**/*',
    'test/**/*',
    'LICENSE',
    'Gemfile'
  ]
  s.test_files  = Dir['test/**/*']
  s.summary     = 'A puppet linter to detect security code smells.'
  s.description = <<-EOF
    Checks puppet manifests for potential security issues.
  EOF

  s.add_dependency             'puppet-lint', '~> 2.0'
end
