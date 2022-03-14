require 'puppet-security-linter'
require 'strong_password'

PuppetLint.new_check(:weak_password) do

    def check
        checker = StrongPassword::StrengthChecker.new
        tokens.each do |token|
            token_value = token.value.downcase
            token_type = token.type.to_s
            next if token.prev_code_token.nil? or token.next_code_token.nil?             
            if ["EQUALS", "FARROW"].include? token_type and ["VARIABLE", "NAME"].include? token.prev_code_token.type.to_s
                left_side_value = token.prev_code_token.value.downcase
                right_side_value = token.next_code_token.value.downcase
                right_side_token = token.next_code_token
                if left_side_value =~ PASSWORD and checker.is_weak?(right_side_value) and right_side_value != '' and token.next_code_token.type.to_s == 'SSTRING'
                    notify :warning, {
                        message: "[SECURITY] Weak Password (line=#{right_side_token.line}, col=#{right_side_token.column}) | Passwords should be strong to be hard to uncover by hackers (weak_password=#{right_side_value}). In any case, you should use kms/heira/vault to store secrets instead.",
                        line:    token.line,
                        column:  token.column,
                        token:   token_value
                    }
                end
             end
      end
   end  
end