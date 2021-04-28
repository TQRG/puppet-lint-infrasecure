require 'puppet-security-linter'

PuppetLint.new_check(:suspicious_comment) do

   SUSPICIOUS = /hack|fixme|ticket|bug|secur|debug|defect|weak/

   def check
      ftokens = get_comments(tokens)
      ftokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if (token_value =~ SUSPICIOUS)
            notify :warning, {
               message: "[SECURITY] Suspicious Comment (line=#{token.line}, col=#{token.column}) | Avoid doing comments containing info about a defect, missing functionality or weakness of the system.",
               line: token.line,
               column: token.column,
               token: token_value
            }
         end
      end
   end
end