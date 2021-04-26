require 'puppet-security-linter'

PuppetLint.new_check(:empty_password) do

   PASSWORD = /pass(word|_|$)|pwd/

   def check
      ftokens = get_string_tokens(tokens,'')
      password = false
      ftokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if ["EQUALS", "FARROW"].include? token.prev_code_token.type.to_s 
            prev_token = token.prev_code_token
            if prev_token.prev_code_token.value.downcase =~ PASSWORD and prev_token.prev_code_token.type.to_s == 'VARIABLE'
               if token_value == ''
                  notify :warning, {
               message: "[SECURITY] Empty Password (line=#{token.line}, col=#{token.column}) | Do not keep the password field empty as for $#{prev_token.prev_code_token.value.downcase} in line #{token.line}. Use kms/heira/vault instead.",
               line:    token.line,
               column:  token.column,
               token:   token_value
            }
               end
            end
         end
      end
   end
end