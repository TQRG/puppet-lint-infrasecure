require 'puppet-security-linter'

PuppetLint.new_check(:hardcode_secret) do
   def check
      invalid_kw_list = ['(', 'undef', 'true', 'false', 'hiera', 'secret', 'union',
                         '$', '{', 'regsubst', 'hiera_hash', 'pick', 'get_ssl_property',
                        'inline_template', 'under', 'mysql_password', '/', 'ssl_ciphersuite', '::']
      tokens.each do |indi_token|
         nxt_token     = indi_token.next_code_token # next token which is not a white space
         if (!nxt_token.nil?) && (!indi_token.nil?)
            token_type   = indi_token.type.to_s ### this gives type for current token

            token_line   = indi_token.line ### this gives type for current token
            nxt_tok_line = nxt_token.line

            nxt_nxt_token =  nxt_token.next_code_token # get the next next token to get key value pair

            if  (!nxt_nxt_token.nil?)
               nxt_nxt_line = nxt_nxt_token.line
               if (token_type.eql? 'NAME') || (token_type.eql? 'VARIABLE')
                  # puts "Token type: #{token_type}"
                  if (token_line==nxt_nxt_line)
                     token_valu   = indi_token.value.downcase
                     nxt_nxt_val  = nxt_nxt_token.value.downcase
                     nxt_nxt_type = nxt_nxt_token.type.to_s  ## to handle false positives,
                     # puts "KEY,PAIR----->#{token_valu}, #{nxt_nxt_val}"
                     # removed these: (token_valu.include? "id") and (token_valu.include? "uuid") || and || (token_valu.include? "token")
                     if ((((token_valu.include? "pwd") || (token_valu.include? "password") || (token_valu.include? "pass") ||
                           (token_valu.include? "key") || (token_valu.include? "crypt") ||
                           (token_valu.include? "secret") || (token_valu.include? "certificate") ||
                           (token_valu.include? "cert") || (token_valu.include? "ssh_key") ||
                           (token_valu.include? "md5") || (token_valu.include? "rsa") || (token_valu.include? "ssl") ||
                           (token_valu.include? "dsa") || (token_valu.include? "user")) && (! token_valu.include? "::") && (! token_valu.include? "passive")) && 
                           ((! token_valu.include? "provider") && (!nxt_nxt_type.eql? 'VARIABLE') && (!invalid_kw_list.include? nxt_nxt_val) && (nxt_nxt_val.length > 1) && (! nxt_nxt_val.include? "::")))
                           # && (nxt_nxt_val.is_a? String)
                           #puts "KEY,PAIR,CURR_TYPE,NEXT_TYPE----->#{token_valu}, #{nxt_nxt_val}, #{token_type}, #{nxt_nxt_type}"
                           notify :warning, {
                              message: 'SECURITY:::HARD_CODED_SECRET_V1:::Do not hard code secrets. This may help an attacker to attack the system. You can use hiera to avoid this issue.@'+token_valu+'='+nxt_nxt_val+'@',
                              line:    indi_token.line,
                              column:  indi_token.column,
                              token:   token_valu
                           }
                     end
                  end
               end
            end
         end
      end
   end
end