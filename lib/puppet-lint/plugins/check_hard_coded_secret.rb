require 'puppet-lint-infrasecure'

PuppetLint.new_check(:hardcoded_secret) do
   def check
      # list of known credentials - not considered secrets by the community (https://puppet.com/docs/pe/2019.8/what_gets_installed_and_where.html#user_and_group_accounts_installed)
      user_default = ['pe-puppet', 'pe-webserver', 'pe-puppetdb', 'pe-postgres', 'pe-console-services', 'pe-orchestration-services','pe-ace-server', 'pe-bolt-server']
      # some were advised by puppet specialists
      invalid_values = ['undefined', 'unset', 'www-data', 'wwwrun', 'www', 'no', 'yes', '[]', 'root']
      ftokens = filter_tokens(tokens)
      ftokens.each do |token|
         next if token.next_code_token.nil?
         token_value = token.value.downcase
         token_type = token.type
         next_token = token.next_code_token
         # accepts <VARIABLE> <EQUALS> secret OR <NAME> <FARROW> secret, checks if <VARIABLE> | <NAME> satisfy SECRETS but not satisfy NON_SECRETS 
         if [:VARIABLE, :NAME].include? token_type and [:EQUALS, :FARROW].include? next_token.type and token_value =~ Rules.secret and !(token_value =~ Rules.nonsecret)
            right_side_type = next_token.next_code_token.type
            right_side_value = next_token.next_code_token.value.downcase
            if [:STRING, :SSTRING].include? right_side_type and right_side_value.length > 1 and !invalid_values.include? right_side_value and !(right_side_value =~ /::|\/|\.|\\/ ) and !user_default.include? right_side_value
               notify :warning, {
                  message: "[SECURITY] Hard Coded Secret (line=#{next_token.next_code_token.line}, col=#{next_token.next_code_token.column}) | Do not keep secrets on your scripts as for $#{token_value} = #{right_side_value} in #{next_token.next_code_token.line}. Use kms/heira/vault instead.",
                  line:    next_token.next_code_token.line,
                  column:  next_token.next_code_token.column,
                  token:   right_side_value,
                  cwe: 'CWE-798'
               }
            end
         end
      end
   end
end