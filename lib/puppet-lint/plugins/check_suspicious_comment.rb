require 'puppet-security-linter'

PuppetLint.new_check(:susp_comments) do
   def check
      ##for comments we need to grab all lines
      lineNo=0
      manifest_lines.each do |single_line|
         lineNo += 1
         ##first check if string starts with #, which is comemnt in Puppet
         if single_line.include? '#'
            ### check if those keywords exist
            single_line=single_line.downcase
            single_line=single_line.strip
            if ( single_line.include?('show_bug') || single_line.include?('hack') ||
                  single_line.include?('fixme')    || single_line.include?('later') ||
                  single_line.include?('later2')   || single_line.include?('todo') ||
                  single_line.include?('ticket')   || single_line.include?('launchpad') ||
                  single_line.include?('bug')
               )
                  notify :warning, {
                     message: 'SECURITY:::SUSPICOUS_COMMENTS:::Do not expose sensitive information=>' + single_line,
                     line: lineNo,
                     column:   5   #no columsn for comment lines so assignning a dummy one to keep puppet-lint happy
                  }
            end
         end
      end
   end
end