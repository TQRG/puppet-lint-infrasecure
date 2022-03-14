require 'puppet-security-linter'

PuppetLint.new_check(:empty_password) do

   def check
      ftokens = get_string_tokens(tokens,'')
      ftokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if ["EQUALS", "FARROW"].include? token.prev_code_token.type.to_s 
            prev_token = token.prev_code_token
            left_side = prev_token.prev_code_token
            if left_side.value.downcase =~ PASSWORD and ["VARIABLE", "NAME"].include? left_side.type.to_s
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