require 'spec_helper'

describe 'cyrillic_homograph_attack' do
    let(:msg) {'[SECURITY] Homograph Attack (line=2, col=35). This link (https://www.аpple.com/phish) has a cyrillic char. These are not rendered by browsers and are sometimes used for phishing attacks.' }
    
    context 'with fix disabled' do
        context 'homograph attack using cyrillic chars not rendered by normal browsers' do
            let(:code) { "
                $apple_phishing = 'https://www.аpple.com/phish'
                $apple_ok = 'https://www.apple.com/ok'
            " }
  
            it 'should detect a single problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning' do
                expect(problems).to contain_warning(msg).on_line(2).in_column(35)
            end
        end
    end
end