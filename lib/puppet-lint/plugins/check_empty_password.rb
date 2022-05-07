require 'puppet-lint-infrasecure'

PuppetLint.new_check(:empty_password) do

   def check
      tokens.each do |token|
         next if token.next_code_token.nil?
         next if token.prev_code_token.nil?
         # accepts (<VARIABLE>|<NAME>) (<EQUALS>|<FARROW>) (<STRING>|<SSTRING>)
         if [:VARIABLE, :NAME].include? token.prev_code_token.type and [:EQUALS, :FARROW].include? token.type and [:STRING, :SSTRING].include? token.next_code_token.type
            left_side_value = token.prev_code_token.value.downcase
            right_side_value = token.next_code_token.value.downcase
            if left_side_value =~ Rules.password and right_side_value  == ''
               notify :warning, {
                  message: "[SECURITY][CWE-258] Empty Password (line=#{token.next_code_token.line}, col=#{token.next_code_token.column}) | Do not keep the password field empty as for $#{token.prev_code_token.value} in line #{token.prev_code_token.line}. Use a stronger password.",
                  line:    token.next_code_token.line,
                  column:  token.next_code_token.column,
                  token:   token.next_code_token.value,
                  cwe: 'CWE-258'
               }
            end
         end
      end
   end
end