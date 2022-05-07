require 'puppet-lint-infrasecure'

PuppetLint.new_check(:use_http_without_tls) do
   def check
      if Config.regex.whitelist
         wtokens = filter_whitelist(tokens)
      else
         wtokens = tokens
      end
      wtokens.each do |token|
         next if token.next_code_token.nil?
         next if token.prev_code_token.nil?   
         # accepts (<VARIABLE>|<NAME>) (<EQUALS>|<FARROW>) (<STRING>|<SSTRING>)
         if [:EQUALS, :FARROW].include? token.prev_code_token.type and [:STRING, :SSTRING].include? token.type
            right_side_value = token.value.downcase
         
            if (right_side_value =~ Rules.http)
               notify :warning, {
               message: "[SECURITY][CWE-319] HTTP without TLS (line=#{token.line}, col=#{token.column}) | Do not use HTTP without TLS as in #{token.value}. This may cause a MITM attack.",
               line: token.line,
               column: token.column,
               token: token.value,
               cwe: 'CWE-319'
               }
            end
         end
      end
   end
end