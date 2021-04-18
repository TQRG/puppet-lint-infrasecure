class PuppetLint::CheckPlugin

   def filter_tokens_per_value(tokens, token)
      ftokens=tokens.find_all do |hash|
         (hash.type.to_s == 'SSTRING' || hash.type.to_s == 'STRING') and hash.value.downcase.include? token
      end
      return ftokens
   end

   def filter_block(tokens, block_name)
      is_block = 0      
      ftokens=tokens.find_all do |hash|
         if hash.value.downcase.include? block_name
            is_block = 1
         end
         if is_block == 1 && hash.type.to_s == "RBRACE"
            is_block = 0
         end
         if is_block == 0 && hash.type.to_s != "RBRACE"
            (hash.type.to_s == 'NAME' || hash.type.to_s == 'SSTRING' || hash.type.to_s == 'STRING')
         end
      end
      return ftokens
   end
end