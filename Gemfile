# The development group is intended for developer tooling. CI will never install this.
group :development do
end

# The test group is used for static validations and unit tests in gha-puppet's
# basic and beaker gha-puppet workflows.
# Consider using https://github.com/voxpupuli/voxpupuli-test
group :test do
  # Require the latest Puppet by default unless a specific version was requested
  # CI will typically set it to '~> 7.0' to get 7.x
  gem 'puppet', ENV['PUPPET_GEM_VERSION'] || '>= 0', require: false
  # Needed to build the test matrix based on metadata
  gem 'puppet_metadata', '~> 1.0',  require: false
  # Needed for the rake tasks
  gem 'puppetlabs_spec_helper', '>= 2.16.0', '< 5', require: false
  # Rubocop versions are also specific so it's recommended
  # to be precise. Can be turned off via a parameter
  gem 'rubocop', require: false
end

# The system_tests group is used in gha-puppet's beaker workflow.
# Consider using https://github.com/voxpupuli/voxpupuli-acceptance
group :system_tests do
  gem 'beaker', require: false
  gem 'beaker-docker', require: false
  gem 'beaker-rspec', require: false
end

# The release group is used in gha-puppet's release workflow
# Consider using https://github.com/voxpupuli/voxpupuli-release
group :release do
  gem 'puppet-blacksmith', '~> 6.0', require: false
end
