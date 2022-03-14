require 'puppet-security-linter'

PuppetLint.new_check(:invalid_ip_addr_binding) do
   
   IP_ADDR_BIN_REGEX = /^((http(s)?:\/\/)?0.0.0.0(:\d{1,5})?)$/ 
   
   def check
      ftokens = get_tokens(tokens,"0.0.0.0")
      ftokens.each do |token|
         token_value = token.value.downcase
         if [:EQUALS, :FARROW].include? token.prev_code_token.type 
            prev_token = token.prev_code_token
            left_side = prev_token.prev_code_token
            if token_value =~ IP_ADDR_BIN_REGEX and [:VARIABLE, :NAME].include? left_side.type
               notify :warning, {
               message: "[SECURITY] Invalid IP Address Binding (line=#{token.line}, col=#{token.column}) | Don\'t bind your host to #{token_value}. This config allows connections from every possible network. Restrict your available IPs.",
               line:    token.line,
               column:  token.column,
               token:   token_value
            }
            end
         end
      end
   end
end