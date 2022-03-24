require 'puppet-lint-infrasecure'

PuppetLint.new_check(:admin_by_default) do

   def check
        ftokens = get_tokens(tokens,'admin')
        ftokens.each do |token|
         token_value = token.value.downcase
         if [:EQUALS, :FARROW].include? token.prev_code_token.type
            prev_token = token.prev_code_token
            left_side = prev_token.prev_code_token
            if left_side.value.downcase =~ Rules.credentials and [:VARIABLE, :NAME].include? left_side.type
               if token_value == 'admin'
                  notify :warning, {
               message: "[SECURITY] Admin by default (line=#{token.line}, col=#{token.column}) | Do not make user/password as admin as for $#{prev_token.prev_code_token.value.downcase} in line #{token.line}. This can be easily exploited.",
               line:    token.line,
               column:  token.column,
               token:   token_value,
               cwe: 'CWE-250'
            }
               end
            end
         end
      end
   end
end