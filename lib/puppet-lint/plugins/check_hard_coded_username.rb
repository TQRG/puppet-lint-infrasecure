require 'puppet-lint-infrasecure'

PuppetLint.new_check(:hardcoded_secret_username) do
   def check
      # list of known credentials - not considered secrets by the community (https://puppet.com/docs/pe/2019.8/what_gets_installed_and_where.html#user_and_group_accounts_installed)
      user_default = ['pe-puppet', 'pe-webserver', 'pe-puppetdb', 'pe-postgres', 'pe-console-services', 'pe-orchestration-services','pe-ace-server', 'pe-bolt-server']
      # some were advised by puppet specialists
      invalid_values = ['undefined', 'unset', 'www-data', 'wwwrun', 'www', 'no', 'yes', '[]', 'undef', 'true', 'false', 'changeit', 'changeme', 'root', 'admin', 'none']

      tokens.each do |token|
         next if token.next_code_token.nil?
         next if token.prev_code_token.nil?
         # accepts (<VARIABLE>|<NAME>) (<EQUALS>|<FARROW>) !(<STRING>|<SSTRING>)
         if [:VARIABLE, :NAME].include? token.prev_code_token.type and [:EQUALS, :FARROW].include? token.type and [:STRING, :SSTRING].include? token.next_code_token.type
            left_side_value = token.prev_code_token.value.downcase
            right_side_value = token.next_code_token.value.downcase
            if left_side_value =~ Rules.username and !(left_side_value =~ Rules.nonsecret)
               if !(right_side_value =~ Rules.placeholder) and right_side_value.length > 1 and !right_side_value[/\/.*(\/)+/] and !(user_default.include? right_side_value) and !(invalid_values.include? right_side_value)
                     notify :warning, {
                        message: "[SECURITY][CWE-798] Hard Coded Username (line=#{token.next_code_token.line}, col=#{token.next_code_token.column}) | Do not keep secrets on your scripts as for $#{token.prev_code_token.value} = #{token.next_code_token.value} in line #{token.next_code_token.line}. Store secrets in a vault instead.",
                        line:    token.next_code_token.line,
                        column:  token.next_code_token.column,
                        token:   right_side_value,
                        cwe: 'CWE-798'
                     }
               end
            end
         end
      end
   end
end