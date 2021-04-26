require 'puppet-security-linter'

PuppetLint.new_check(:invalid_ip_addr_binding) do
   
   IP_ADDR_BIN_REGEX = /^((http(s)?:\/\/)?0.0.0.0(:\d{1,5})?)$/ 
   
   def check
      ftokens = get_string_tokens(tokens,"0.0.0.0")
      ftokens.each do |token|
         token_value = token.value.downcase
         token_type = token.type.to_s
         if (token_value =~ IP_ADDR_BIN_REGEX and token.prev_code_token.type.to_s != "ISEQUAL")
            notify :warning, {
               message: "[SECURITY] Invalid IP Address Binding (line=#{token.line}, col=#{token.column}) | Don\'t bind your host to #{token_value}. This config allows connections from every possible network. Restrict your available IPs.",
               line: token.line,
               column: token.column,
               token: token_value
            }
         end
      end
   end
end