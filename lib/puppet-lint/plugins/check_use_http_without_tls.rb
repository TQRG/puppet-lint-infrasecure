PuppetLint.new_check(:use_http_without_tls) do
   def check
      tokens.each do |indi_token|
         token_valu = indi_token.value ### this gives each token
         token_valu = token_valu.downcase
         token_type = indi_token.type.to_s
         if (token_valu =~ /^http:\/\/.+/ ) && (['STRING', 'SSTRING', 'DQPRE'].include? token_type)
            notify :warning, {
               message: 'SECURITY:::HTTP:::Do not use HTTP without TLS. This may cause a man in the middle attack. Use TLS with HTTP.@'+token_valu+'@',
               line: indi_token.line,
               column: indi_token.column,
               token: token_valu
            }
         end
      end
   end
end