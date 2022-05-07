require 'puppet-lint-infrasecure'

PuppetLint.new_check(:invalid_ip_addr_binding) do   
   def check
      tokens.each do |token|
         next if token.next_code_token.nil?
         next if token.prev_code_token.nil?
         # accepts (<VARIABLE>|<NAME>) (<EQUALS>|<FARROW>) (<STRING>|<SSTRING>)
         if [:VARIABLE, :NAME].include? token.prev_code_token.type and [:EQUALS, :FARROW].include? token.type and [:STRING, :SSTRING].include? token.next_code_token.type
            left_side_value = token.prev_code_token.value.downcase
            right_side_value = token.next_code_token.value.downcase
            if right_side_value =~ Rules.ip_addr_bind
               notify :warning, {
               message: "[SECURITY][CWE-284] Invalid IP Address Binding (line=#{token.next_code_token.line}, col=#{token.next_code_token.column}) | Don\'t bind your host to #{token.next_code_token.value}. This config allows connections from every possible network. Restrict your available IPs.",
               line:    token.next_code_token.line,
               column:  token.next_code_token.column,
               token:   token.next_code_token.value,
               cwe: 'CWE-284'
               }
            end
         end
      end
   end
end