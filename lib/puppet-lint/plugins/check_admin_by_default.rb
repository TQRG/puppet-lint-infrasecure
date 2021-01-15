PuppetLint.new_check(:admin_by_default) do
    def check
      tokens.each do |indi_token|
         nxt_token     = indi_token.next_code_token # next token which is not a white space
         if (!nxt_token.nil?) && (!indi_token.nil?)
            token_type   = indi_token.type.to_s ### this gives type for current token

            nxt_nxt_token =  nxt_token.next_code_token # get the next next token to get key value pair

            if  (!nxt_nxt_token.nil?)
               token_line      = indi_token.line ### this gives type for current token
               nxt_tok_line    = nxt_token.line
               nxt_nxt_tok_lin = nxt_nxt_token.line
               if (token_type.eql? 'NAME') || (token_type.eql? 'VARIABLE') || (token_type.eql? 'SSTRING')
                  nxt_typ = nxt_token.type.to_s
                  nxt_nxt_typ=nxt_nxt_token.type.to_s
                  if (token_line==nxt_tok_line) && (token_line==nxt_nxt_tok_lin)
                     if (token_type.eql? 'VARIABLE') && (nxt_typ.eql? 'EQUALS') && (nxt_nxt_typ.eql? 'SSTRING')
                          # puts "ONE,TWO,THREE----->#{token_type}, #{nxt_typ}, #{nxt_nxt_typ}"
                          nxt_nxt_val = nxt_nxt_token.value.downcase
                          token_val   = indi_token.value.downcase
                          if ((nxt_nxt_val.include? 'admin') && (token_val.include? 'user')) ||
                             ((token_val.include? 'admin') && (token_val.include? 'user'))
                             notify :warning, {
                               message: 'SECURITY:::ADMIN_BY_DEFAULT:::Do not make default user as admin. This violates the secure by design principle.@'+token_val+'='+nxt_nxt_val+'@',
                               line:    indi_token.line,
                               column:  indi_token.column,
                               token:   token_val
                             }
                           end
                     end
                  end
               end
            end
         end
      end
   end
end