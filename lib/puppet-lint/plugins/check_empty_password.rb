require 'puppet-lint-infrasecure'

PuppetLint.new_check(:empty_password) do

   def check
      ftokens = get_string_tokens(tokens,'')
      ftokens.each do |token|
         token_value = token.value.downcase
         if [:EQUALS, :FARROW].include? token.prev_code_token.type 
            prev_token = token.prev_code_token
            left_side = prev_token.prev_code_token
            if left_side.value.downcase =~ Rules.password and [:VARIABLE, :NAME].include? left_side.type
               if token_value == ''
                  notify :warning, {
               message: "[SECURITY] Empty Password (line=#{token.line}, col=#{token.column}) | Do not keep the password field empty as for $#{prev_token.prev_code_token.value.downcase} in line #{token.line}. Use kms/heira/vault instead.",
               line:    token.line,
               column:  token.column,
               token:   token_value,
               cwe: 'CWE-258'
            }
               end
            end
         end
      end
   end
end