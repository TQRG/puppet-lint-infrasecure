require 'spec_helper'

describe 'weak_password' do
    let(:msg) { '[SECURITY][CWE-521] Weak Password (line=9, col=20) | Passwords should be strong to be hard to uncover by hackers (weak_password=12345678, entropy=10). Recommendation is to use a password with at least 18 bits of entropy. In any case, secrets should be stored in services like kms/heira/vault not in plain text.' }
    
    context 'with fix disabled' do
        context 'code using weak password' do
            let(:code) { "
            $sievedir      = '/var/imap/sieve'
            $statedir      = '/var/imap'
            $spooldir      = '/var/spool/imap'
            $lmtp_external   = get_var('imap_lmtp_external', false)
          
            $dashboard_password = '!$jNb#khug679!'
            $template_imapd = template_version($version_imapd, '2.3.12_p2@2.3.13@:2.3.12_p2,', '2.3.12_p2')
            $pwd = '12345678'

            " }
  
            it 'should detect a single problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning' do
                expect(problems).to contain_warning(msg).on_line(9).in_column(20)
            end
        end
    end
end