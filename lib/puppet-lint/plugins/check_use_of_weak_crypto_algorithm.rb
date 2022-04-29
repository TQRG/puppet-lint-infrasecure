PuppetLint.new_check(:use_of_weak_crypto_algorithm) do
   def check
      tokens.each do |indi_token|
         token_valu = indi_token.value ### this gives each token
         token_valu = token_valu.downcase
         token_type = indi_token.type.to_s
         if ((((token_valu.include? "md5") || (token_valu.include? "sha1")) && (['NAME', 'FUNCTION_NAME'].include? token_type)) || 
            (((token_valu == "md5") || (token_valu == "sha1")) && (['STRING', 'SSTRING'].include? token_type)))
            notify :warning, {
               message: 'SECURITY:::MD5:::Do not use MD5 or SHA1, as they have security weakness. Use SHA-512.@' + token_valu+'@',
               line: indi_token.line,
               column: indi_token.column,
               token: token_valu
            }
         end
      end
   end  
end