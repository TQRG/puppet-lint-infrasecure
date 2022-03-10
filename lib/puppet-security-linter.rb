require 'puppet-lint'
require 'puppet-lint/linter'
require 'puppet-lint/config'
require 'dotenv/load'
require 'json'

Dotenv.load('.env')

module PuppetSecurityLinter
    class << self
      attr_accessor :configuration
    end
  
    def self.configuration
      @configuration ||= Configuration.new
    end
  
    def self.reset
      @configuration = Configuration.new
    end
  
    def self.configure
      yield(configuration)
    end
end

config = PuppetSecurityLinter::Configuration.new
if ENV['WHITELIST'] != ''
  links = File.open(ENV['WHITELIST']).read.gsub("\n",'|')
  config.whitelist = Regexp.new links
else
  puts 'Whitelist is not configured!'
end

PuppetSecurityLinter.configuration = config

