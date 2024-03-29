require 'puppet-lint-infrasecure'

PuppetLint.new_check(:malicious_dependency) do
   def check
      ftokens = get_dependencies(tokens)
      ftokens.each do |token|
         version = token[:token].next_code_token.value.downcase
         if version.include? "v"
            version = version.gsub("v", "")
         end
         dependency = token[:dependency]
         cves = get_malicious_cves(dependency, version)
         if !cves.nil?
            notify :warning, {
               message: "[SECURITY][CWE-829] Malicious Dependency (line=#{token[:token].line}, col=#{token[:token].column}) | This software is using a third-party library/software (#{dependency} v#{version}) affected by known CVEs (#{cves.join(', ')}).",
               line: token[:token].line,
               column: token[:token].column,
               token: token[:token].prev_code_token.value.downcase,
               cwe: 'CWE-829'
            }
         end
      end
   end
end