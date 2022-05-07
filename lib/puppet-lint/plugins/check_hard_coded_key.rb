require 'puppet-lint-infrasecure'

PuppetLint.new_check(:hardcoded_secret_key) do
   def check
      tokens.each do |token|
         next if token.next_code_token.nil?
         next if token.prev_code_token.nil?
         # accepts (<VARIABLE>|<NAME>) (<EQUALS>|<FARROW>) (<STRING>|<SSTRING>)
         if [:VARIABLE, :NAME].include? token.prev_code_token.type and [:EQUALS, :FARROW].include? token.type and [:STRING, :SSTRING].include? token.next_code_token.type
            left_side_value = token.prev_code_token.value.downcase
            right_side_value = token.next_code_token.value.downcase
            # checks left side (<VARIABLE>|<NAME>)
            if left_side_value =~ Rules.key and !(left_side_value =~ Rules.nonsecret)
               # checks right side (<STRING>|<SSTRING>)
               if !(right_side_value =~ Rules.placeholder) and right_side_value.length > 1 and !right_side_value[/\/.*(\/)+/]
                  notify :warning, {
                     message: "[SECURITY][CWE-321] Hard Coded Key (line=#{token.next_code_token.line}, col=#{token.next_code_token.column}) | Do not keep secrets on your scripts as for $#{token.prev_code_token.value} = #{token.next_code_token.value} in line #{token.next_code_token.line}. Store secrets in a vault instead.",
                     line:    token.next_code_token.line,
                     column:  token.next_code_token.column,
                     token:   right_side_value,
                     cwe: 'CWE-321'
                  }
               end
            end
         end
      end
   end
end