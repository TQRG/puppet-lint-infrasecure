require 'puppet-security-linter'

PuppetLint.new_check(:use_http_without_tls) do

   HTTP = /^http:\/\/.+/

   def check
      resources = ['apt::source', '::apt::source', 'wget::fetch', 'yumrepo', 'yum::', 'aptly::mirror', 'util::system_package', 'yum::managed_yumrepo']
      ptokens = filter_resources(tokens, resources)
      keywords = ['backport', 'key', 'download', 'uri', 'mirror']
      ctokens = filter_variables(ptokens, keywords)
      if PuppetSecurityLinter.configuration.whitelist
         wtokens = filter_whitelist(ctokens)
      else
         wtokens = ptokens
      end
      wtokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if (token_value =~ HTTP)
            notify :warning, {
               message: "[SECURITY] HTTP without TLS (line=#{token.line}, col=#{token.column}) | Do not use HTTP without TLS as in #{token_value}. This may cause a MITM attack.",
               line: token.line,
               column: token.column,
               token: token_value
            }
         end
      end
   end
end