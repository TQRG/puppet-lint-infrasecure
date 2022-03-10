require 'puppet-security-linter'

PuppetLint.new_check(:malicious_dependency) do

   DEPENDENCIES = /(postgresql|docker|mongodb|mysql|nginx|nodejs|ntp|rabbitmq|redis|ruby)_version/

   def check
      ftokens = remove_whitespace(tokens)
      ftokens.each do |token|
         next if token.prev_code_token.nil? or token.next_code_token.nil?             
         variable_name = token.prev_code_token.value.downcase
         if ["EQUALS", "FARROW"].include? token.type.to_s and DEPENDENCIES =~ variable_name
            version = token.next_code_token.value.downcase
            cves = get_dependency(variable_name, version)
         end

         if !cves.nil?
            notify :warning, {
               message: "[SECURITY] Malicious Dependency (line=#{token.line}, col=#{token.column}) | This software is using a third-party library/software affected by known CVEs (#{cves.join(', ')}).",
               line: token.line,
               column: token.column,
               token: variable_name
            }
         end
      end
   end
end