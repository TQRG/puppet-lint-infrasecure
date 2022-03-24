require 'puppet-lint'
require 'puppet-lint/linter'
require 'puppet-lint-infrasecure/regex'
require 'puppet-lint-infrasecure/rules'
require 'dotenv/load'
require 'json'
require 'yaml'


def get_root()
  return File.dirname(File.expand_path(__FILE__))
end 

def get_config(root)
  return File.join(root, 'puppet-lint-infrasecure/config/')
end

def get_depen(root)
  return File.join(root, 'puppet-lint-infrasecure/dependencies/')
end

def load_regex(cpath)
  regex = Regex::FromConfig.new()
  # load dependencies list
  dpath = "#{cpath}dependencies.yml"
  regex.load_dependencies(dpath)

  # if a .env files exists
  if File.exist?('.env')
    # loads .env file
    Dotenv.load('.env')
    # if config for WHITELIST exists
    if ENV.has_key?('WHITELIST')
      # loads whitelist urls
      if ENV['WHITELIST'] != '' and File.exist?(ENV['WHITELIST'])
        regex.load_whitelist(ENV['WHITELIST'])
        return regex
      end
    end
  end
  # config default list
  wpath = "#{cpath}whitelist"
  regex.load_whitelist(wpath)
  return regex
end

module Config
  class << self
    attr_accessor :regex
    attr_accessor :path
  end

  def self.regex
    @regex ||= regex.new
  end

  def self.dpath
    @path ||= get_depen(get_root())
  end
end

Config.regex = load_regex(get_config(get_root()))