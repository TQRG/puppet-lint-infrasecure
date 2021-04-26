require 'puppet-security-linter'

PuppetLint.new_check(:apple_phishing_attack) do

   SITE_W_CYRILLIC = /^(http(s)?:\/\/)?.*\p{Cyrillic}+/
   
   def check
      ftokens = filter_tokens(tokens)
      tokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if ["STRING", "SSTRING"].include? token_type and token_value =~ SITE_W_CYRILLIC 
            notify :warning, {
               message: "[SECURITY] Phishing Attack (line=#{token.line}, col=#{token.column}). This link (#{token_value}) has a cyrillic char. These are not rendered by browsers and are sometimes used in homograph attacks.",
               line: token.line,
               column: token.column,
               token: token_value
            }
         end
      end
   end
end