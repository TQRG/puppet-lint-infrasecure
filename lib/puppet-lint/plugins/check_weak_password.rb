require 'puppet-lint-infrasecure'
require 'strong_password'

PuppetLint.new_check(:weak_password) do
    def check
        checker = StrongPassword::StrengthChecker.new
        tokens.each do |token|
            token_value = token.value.downcase
            token_type = token.type
            next if token.prev_code_token.nil? or token.next_code_token.nil?             
            if [:EQUALS, :FARROW].include? token_type and [:VARIABLE,:NAME].include? token.prev_code_token.type
                left_side_value = token.prev_code_token.value.downcase
                right_side_value = token.next_code_token.value.downcase
                right_side_token = token.next_code_token
                if left_side_value =~ Rules.password and checker.is_weak?(right_side_value) and right_side_value != '' and token.next_code_token.type == :SSTRING
                    notify :warning, {
                        message: "[SECURITY][CWE-521] Weak Password (line=#{right_side_token.line}, col=#{right_side_token.column}) | Passwords should be strong to be hard to uncover by hackers (weak_password=#{right_side_value}, entropy=#{checker.calculate_entropy(right_side_value)}). You should be using a password with at least 18 bits of entropy. In any case, secrets should be stored in services like kms/heira/vault not in plain text.",
                        line:    right_side_token.line,
                        column:  right_side_token.column,
                        token:   right_side_value,
                        cwe: 'CWE-521'
                    }
                end
             end
      end
   end  
end