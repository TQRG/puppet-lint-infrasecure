require 'puppet-security-linter'

PuppetLint.new_check(:hardcode_secret) do

   SECRETS = /user|usr|pass(word|_|$)|pwd|key|secret/
   NON_SECRETS = /gpg|path|type|buff|zone|mode|tag|header|scheme|length|guid/

   def check
      user_default = ['pe-puppet', 'pe-webserver', 'pe-puppetdb', 'pe-postgres', 'pe-console-services', 'pe-orchestration-services','pe-ace-server', 'pe-bolt-server']
      invalid_values = ['undefined', 'unset', 'www-data', 'wwwrun', 'www', 'no', 'yes', '[]']
      ftokens = filter_tokens(tokens)
      ftokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if token_value =~ SECRETS and !(token_value =~ NON_SECRETS) and token_type == 'VARIABLE' and ["EQUALS", "FARROW"].include? token.next_code_token.type.to_s 
            next_token = token.next_code_token
            assign_side_type = next_token.next_code_token.type.to_s
            assign_side_value = next_token.next_code_token.value.downcase
            if ["STRING", "SSTRING"].include? assign_side_type and assign_side_type != 'VARIABLE' and assign_side_value.length > 3 and !invalid_values.include? assign_side_value and !(assign_side_value =~ /::|\/|\.|\\|\#/) and !user_default.include? assign_side_value
               notify :warning, {
                  message: "[SECURITY] Hard Coded Secret (line=#{token.line}, col=#{token.column}) | Do not keep secrets on your scripts as for $#{token_value} = #{assign_side_value} in #{token.line}. Use kms/heira/vault instead.",
                  line:    token.line,
                  column:  token.column,
                  token:   token_value
               }
            end
         end
      end
   end
end