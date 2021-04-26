require 'puppet-security-linter'

PuppetLint.new_check(:admin_by_default) do

    CREDENTIALS = /user|usr|pass(word|_|$)|pwd/

    def check
        ftokens = get_string_tokens(tokens,'admin')
        ftokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if ["EQUALS", "FARROW"].include? token.prev_code_token.type.to_s 
            prev_token = token.prev_code_token
            if prev_token.prev_code_token.value.downcase =~ CREDENTIALS and prev_token.prev_code_token.type.to_s == 'VARIABLE'
               if token_value == 'admin'
                  notify :warning, {
               message: "[SECURITY] Admin by default (line=#{token.line}, col=#{token.column}) | Do not make user/password as admin as for $#{prev_token.prev_code_token.value.downcase} in line #{token.line}. This can be easily exploited.",
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