begin
  require 'puppetlabs_spec_helper/rake_tasks'
rescue LoadError
  # Allowed to fail, only needed in test
end

begin
  require 'beaker-rspec/rake_task'
rescue LoadError
  # Allowed to fail, only needed in acceptance
end

begin
  require 'puppet_blacksmith/rake_tasks'
rescue LoadError
  # Allowed to fail, only needed in release
end
