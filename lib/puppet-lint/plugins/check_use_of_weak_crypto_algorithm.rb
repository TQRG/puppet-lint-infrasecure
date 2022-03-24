require 'puppet-lint-infrasecure'

PuppetLint.new_check(:use_of_weak_crypto_algorithm) do
   def check
      tokens.each do |token|
         token_value = token.value.downcase
         if !token.next_token.nil?
            next_token_type = token.next_token.type
         end
         if (token_value =~ Rules.poor_crypto) && (next_token_type.eql? :LPAREN)
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