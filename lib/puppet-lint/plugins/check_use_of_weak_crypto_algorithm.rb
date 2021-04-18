require 'puppet-lint-security'

PuppetLint.new_check(:use_of_weak_crypto_algorithm) do

   POOR_CRYPTO= /^(sha1|md5)/

   def check
      tokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if !token.next_token.nil?
            next_token_type = token.next_token.type.to_s
         end
         if (token_value =~ POOR_CRYPTO) && (next_token_type.eql? "LPAREN")
            notify :warning, {
               message: "[SECURITY] Weak Crypto Algorithm (line=#{token.line}, col=#{token.column}) | Do not use #{token_value}, as they have security weakness. Use SHA-512 instead.",
               line: token.line,
               column: token.column,
               token: token_value
         }
         end
      end
   end  
end