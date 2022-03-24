require 'puppet-lint-infrasecure'

PuppetLint.new_check(:suspicious_comment) do
   def check
      ftokens = get_comments(tokens)
      ftokens.each do |token|
         token_value = token.value.downcase
         if (token_value =~ Rules.susp_comment)
            notify :warning, {
               message: "[SECURITY] Suspicious Comment (line=#{token.line}, col=#{token.column}) | Avoid doing comments containing info about a defect, missing functionality or weakness of the system.",
               line: token.line,
               column: token.column,
               token: token_value,
               cwe: 'CWE-546'
            }
         end
      end
   end
end