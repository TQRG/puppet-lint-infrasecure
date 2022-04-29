PuppetLint.new_check(:invalid_ip_addr_binding) do
    def check
      tokens.each do |indi_token|
         token_valu = indi_token.value ### this gives each token
         token_valu = token_valu.downcase
         token_type = indi_token.type.to_s
         if (token_valu =~ /^((http(s)?:\/\/)?0.0.0.0(:\d{1,5}|\/\d)?)$/) && (!token_type.eql? "COMMENT")
            notify :warning, {
               message: 'SECURITY:::BINDING_TO_ALL:::Do not bind to 0.0.0.0. This may cause a DDOS attack. Restrict your available IPs.',
               line: indi_token.line,
               column: indi_token.column,
               token: token_valu
            }
         end
      end
   end
end