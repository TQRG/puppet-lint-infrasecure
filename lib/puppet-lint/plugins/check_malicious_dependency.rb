require 'puppet-security-linter'

PuppetLint.new_check(:malicious_dependency) do
   
   DEPENDENCIES = /(activemq|apt|cassandra|docker|elasticsearch|jenkins|jira|kafka|kubernetes|mongodb|gerrit|gitlab|grafana|haproxy|hiera|nagios_core|puppet_agent|puppet_db|wget|zabbix|mysql|nginx|nodejs|ntp|openstack|openvpn|postgresql|rabbitmq|redis|ruby|sqlite|systemd|terraform|tomcat|vault|yum)/

   def check
      ftokens = get_dependencies(tokens)
      ftokens.each do |token|
         version = token[:token].next_code_token.value.downcase
         dependency = token[:dependency]
         cves = get_malicious_cves(dependency, version)
         if !cves.nil?
            notify :warning, {
               message: "[SECURITY] Malicious Dependency (line=#{token[:token].line}, col=#{token[:token].column}) | This software is using a third-party library/software (#{dependency} v#{version}) affected by known CVEs (#{cves.join(', ')}).",
               line: token[:token].line,
               column: token[:token].column,
               token: token[:token].prev_code_token.value.downcase
            }
         end
      end
   end
end