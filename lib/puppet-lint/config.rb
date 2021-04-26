module PuppetSecurityLinter
    class Configuration
      attr_accessor :whitelist
  
      def initialize
        @whitelist = nil
      end
    end
  end