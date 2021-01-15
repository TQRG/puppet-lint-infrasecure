PuppetLint.new_check(:trailing_newline) do
    def check
        last_token = tokens.last
      
        unless last_token.type == :NEWLINE
          # notify :warning, {
          #   :message => 'expected newline at the end of the file',
          #   :line    => last_token.line,
          #   :column  => manifest_lines.last.length,
          # }
        end
      end
  end