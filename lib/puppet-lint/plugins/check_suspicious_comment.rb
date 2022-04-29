PuppetLint.new_check(:suspicious_comment) do
   def check
      tokens.each do |token|
         if [:COMMENT, :MLCOMMENT, :SLASH_COMMENT].include? token.type 
            comment = token.value.downcase
            if  ((comment.include?('hack') ||
               comment.include?('fixme')    || 
               comment.include?('ticket')   || comment.include?('launchpad') ||
               comment.include?('bug')) && (!comment.include?('debug'))
                  )
                  notify :warning, {
                     message: 'SECURITY:::SUSPICOUS_COMMENTS:::Do not expose sensitive information@' + comment+'@',
                     line: token.line,
                     column:   token.column   #no columsn for comment lines so assignning a dummy one to keep puppet-lint happy
                  }
            end
         end
      end
   end
end