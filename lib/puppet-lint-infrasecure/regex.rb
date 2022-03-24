module Regex  
  class FromConfig
    attr_accessor :whitelist, :dependencies

    def initialize()
      @whitelist = nil
      @dependencies = nil
    end

    def load_whitelist(path)
      @whitelist = Regexp.new File.open(path).read.gsub("\n",'|')
    end

    def load_dependencies(path)
      @dependencies =  Regexp.new YAML.load_file(path).join('|')
    end
  end
end
