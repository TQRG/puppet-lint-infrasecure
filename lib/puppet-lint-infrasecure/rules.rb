module Rules
    class << self
        attr_accessor :password
        attr_accessor :credentials
        attr_accessor :cyrillic
        attr_accessor :secret
        attr_accessor :nonsecret
        attr_accessor :ip_addr_bind
        attr_accessor :susp_comment
        attr_accessor :http
        attr_accessor :poor_crypto
        attr_accessor :whitelist
        attr_accessor :dependencies
    end
  
    def self.password
      @password ||= /pass(word|_|$)|pwd/
    end

    def self.secret
        @secret ||= /user|usr|pass(word|_|$)|pwd|(pvt|priv)+.*(cert|key|rsa|secret|ssl)+/
    end

    def self.key
        @key ||= /(cert|key|rsa|secret|ssl)+/
    end

    def self.privkey
        @key ||= /(pvt|priv)+.*(cert|key|rsa|secret|ssl)+/
    end


    def self.username
        @username ||= /user|usr/
    end

    def self.nonsecret
        @nonsecret ||= /gpg|path|type|buff|zone|mode|tag|header|scheme|length|guid/
    end

    def self.credentials
        @credentials ||= /user|usr|pass(word|_|$)|pwd/
    end

    def self.placeholder
        @placeholder ||= /\${.*}|(\$)?.*::.*(::)?/
    end

    def self.cyrillic
        @cyrillic ||= /^(http(s)?:\/\/)?.*\p{Cyrillic}+/
    end

    def self.ip_addr_bind
        @ip_addr_bind ||= /^((http(s)?:\/\/)?0.0.0.0(:\d{1,5})?)$/
    end

    def self.susp_comment
        @susp_comment ||= /hack|fixme|ticket|bug|hack|checkme|secur|debug|defect|weak/
    end

    def self.http
        @http ||=  /^http:\/\/.+/
    end

    def self.poor_crypto
        @poor_crypto ||=  /^(sha1|md5)/
    end
end