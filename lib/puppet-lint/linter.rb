class PuppetLint::CheckPlugin

   DEPENDENCIES = /(python|activemq|apt|cassandra|docker|elasticsearch|jenkins|jira|kafka|kubernetes|mongodb|gerrit|gitlab|grafana|haproxy|hiera|nagios_core|puppet_agent|puppet_db|wget|zabbix|mysql|nginx|nodejs|ntp|openstack|openvpn|postgresql|rabbitmq|redis|ruby|sqlite|systemd|terraform|tomcat|vault|yum)/
   DEPENDENCIES_VER = /(python|activemq|apt|cassandra|docker|elasticsearch|jenkins|jira|kafka|kubernetes|mongodb|gerrit|gitlab|grafana|haproxy|hiera|nagios_core|puppet_agent|puppet_db|wget|zabbix|mysql|nginx|nodejs|ntp|openstack|openvpn|postgresql|rabbitmq|redis|ruby|sqlite|systemd|terraform|tomcat|vault|yum)_version/

   def get_malicious_cves(dependency, version)
      path = File.dirname(File.realpath(__FILE__))
      path << "/dependencies/"
      path << dependency
      path << ".json"
      cves = JSON.parse(File.read(path))
      if !cves[version].nil?
         return cves[version]
      end
   end

   def get_dependencies(tokens)
      is_resource = false
      ftokens = []
      dependency = ''
      tokens.each do |token|

         is_next_brace = (not token.next_code_token.nil? and token.next_code_token.type == :LBRACE)
         is_prev_brace = (not token.prev_code_token.nil? and token.prev_code_token.type == :LBRACE)

         if (token.value.downcase[DEPENDENCIES] and token.type == :NAME and is_next_brace) or (token.value.downcase[DEPENDENCIES] and token.type == :SSTRING and is_prev_brace)
            is_resource = true
            dependency = token.value.downcase[DEPENDENCIES]
         end 

         if is_resource and token.type == :RBRACE
            is_resource = false
         end

         
         if not is_resource and not token.next_code_token.nil? 
            if token.value.downcase[DEPENDENCIES_VER]
               dependency = token.value.downcase[DEPENDENCIES]
               variable_name = "#{dependency}_version"
               if token.value.downcase == variable_name and [:EQUALS, :FARROW].include? token.next_code_token.type
                  ftokens += [{"token": token.next_code_token, "dependency": dependency}]
               end
            end
         end
         
         is_assign = (not token.prev_code_token.nil? and not token.next_code_token.nil?)
         is_version = (is_assign and token.prev_code_token.value.downcase =~ /version/)
         
         if is_resource and is_version and [:EQUALS, :FARROW].include? token.type and ![:VARIABLE, :NAME].include? token.next_code_token.type
            if !token.prev_code_token.value.downcase[DEPENDENCIES].eql? dependency and token.prev_code_token.value.downcase[DEPENDENCIES]
               ftokens += [{"token": token, "dependency": token.prev_code_token.value.downcase[DEPENDENCIES]}]
            else
               ftokens += [{"token": token, "dependency": dependency}]
            end
         end

      end
      return ftokens
   end

   def get_string_tokens(tokens, token)
      ftokens=tokens.find_all do |hash|
         [:SSTRING, :STRING].include? hash.type and hash.value.downcase.include? token
      end
      return ftokens
   end

   def get_tokens(tokens, token)
      ftokens=tokens.find_all do |hash|
         [:NAME, :VARIABLE, :SSTRING, :STRING].include? hash.type and hash.value.downcase.include? token
      end
      return ftokens
   end

   def get_comments(tokens)
      ftokens=tokens.find_all do |hash|
         [:COMMENT, :MLCOMMENT, :SLASH_COMMENT].include? hash.type
      end
      return ftokens
   end

   def filter_resources(tokens, resources)
      is_resource = false  
      brackets = 0
      ftokens=tokens.find_all do |hash|
         
         if resources.include? hash.value.downcase
            is_resource = true
         elsif is_resource and hash.type == :LBRACE
            brackets += 1
         elsif is_resource and hash.type == :RBRACE
            brackets -=1
         end

         if is_resource and hash.type == :RBRACE and brackets == 0
            is_resource = false
         end

         if !is_resource
            [:NAME, :VARIABLE, :SSTRING, :STRING].include? hash.type
         end
      end
      return ftokens
   end

   def filter_whitelist(tokens)
      whitelist=PuppetSecurityLinter.configuration.whitelist 
      ftokens=tokens.find_all do |hash|
         !(whitelist =~ hash.value.downcase)
      end
      return ftokens
   end

   def filter_tokens_per_value(tokens, token)
      ftokens=tokens.find_all do |hash|
         [:NAME, :SSTRING, :STRING].include? hash.type and !hash.value.downcase.include? token
      end
      return ftokens
   end

   def filter_tokens(tokens)
      ftokens=tokens.find_all do |hash|
         [:NAME, :VARIABLE, :SSTRING, :STRING].include? hash.type
      end
      return ftokens
   end

   def filter_variables(tokens, keywords)
      line = -1
      kw_regex = Regexp.new keywords.join("|")
      ftokens=tokens.find_all do |hash|
         if [:NAME, :VARIABLE].include? hash.type and hash.value.downcase =~ kw_regex
            line = hash.line
         elsif hash.line != line
            hash
         end
      end
   end
end