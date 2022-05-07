require 'puppet-lint-infrasecure'

PuppetLint.new_check(:cyrillic_homograph_attack) do   
   def check
      tokens.each do |token|
         next if token.next_code_token.nil?
         next if token.prev_code_token.nil?
         # accepts (<VARIABLE>|<NAME>) (<EQUALS>|<FARROW>) (<STRING>|<SSTRING>)
         if [:VARIABLE, :NAME].include? token.prev_code_token.type and [:EQUALS, :FARROW].include? token.type and [:STRING, :SSTRING].include? token.next_code_token.type
            left_side_value = token.prev_code_token.value.downcase
            right_side_value = token.next_code_token.value.downcase
            # checks (<STRING>|<SSTRING>)
            if right_side_value =~ Rules.cyrillic 
               notify :warning, {
                  message: "[SECURITY][CWE-1007] Homograph Attack (line=#{token.next_code_token.line}, col=#{token.next_code_token.column}). This link (#{right_side_value}) has a cyrillic char. These chars are not rendered by browsers and are sometimes used for phishing attacks. It can also result in typosquatting attacks.",
                  line: token.next_code_token.line,
                  column: token.next_code_token.column,
                  token: token.next_code_token.value,
                  cwe: 'CWE-1007'
               }
            end
         end
      end
   end
end