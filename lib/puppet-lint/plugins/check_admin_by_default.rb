require 'puppet-lint-infrasecure'

PuppetLint.new_check(:admin_by_default) do

   def check
      tokens.each do |token|
         next if token.next_code_token.nil?
         next if token.prev_code_token.nil?
         # accepts (<VARIABLE>|<NAME>) (<EQUALS>|<FARROW>) (<STRING>|<SSTRING>)
         if [:VARIABLE, :NAME].include? token.prev_code_token.type and [:EQUALS, :FARROW].include? token.type and [:STRING, :SSTRING].include? token.next_code_token.type
            left_side_value = token.prev_code_token.value.downcase
            right_side_value = token.next_code_token.value.downcase
            
            # left side checkers (<VARIABLE>|<NAME>)
            if !(left_side_value =~ Rules.nonsecret) and left_side_value =~ Rules.username and !left_side_value[/(admin|root)/]
               # right side checkers (<STRING>|<SSTRING>)
               if !(right_side_value =~ Rules.placeholder) and right_side_value.length > 1 and !(right_side_value =~ /\/.*./ )
                  # final check
                  if ['admin', 'root'].include? right_side_value
                     notify :warning, {
                        message: "[SECURITY][CWE-250] Admin by default (line=#{token.line}, col=#{token.column}) | Do not make user as admin as for $#{left_side_value} in line #{token.line}. This can be easily exploited.",
                        line:    token.line,
                        column:  token.column,
                        token:   right_side_value,
                        cwe: 'CWE-250'
                     }
                  end
               end
            end
         end
      end
   end
end