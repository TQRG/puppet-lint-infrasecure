require File.expand_path('lib/puppet_sec_linter/version', __dir__)

Gem::Specification.new do |s|
  s.name = 'puppet_sec_linter'
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
    'lib/puppet_sec_linter.rb',
    'lib/**/**.rb',
    'LICENSE',
    'Gemfile'
  ]
  s.require_paths = ["lib"]

  s.add_dependency             'puppet-lint', '~> 2.0'
end
