require 'spec_helper'

describe 'suspicious_comment' do
    let(:msg) { '[SECURITY][CWE-546] Suspicious Comment (line=8, col=9) | Avoid doing comments containing info about a defect, missing functionality or weakness of the system.' }
    
    context 'with fix disabled' do
        context 'code with suspicious comment' do
            let(:code) { "
    if $::realm == 'labs' {
        # The 'ssh-key-ldap-lookup' tool is called during login ssh via AuthorizedKeysCommand.  It
        #  returns public keys from ldap for the specified username.
        # It is in /usr/sbin and not /usr/local/sbin because on Debian /usr/local is 0775
        # and sshd refuses to use anything under /usr/local because of the permissive group
        # permission there (and group is set to 'staff', slightly different from root).
        # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=538392
        if os_version('debian == jessie') {
            file { '/usr/sbin/ssh-key-ldap-lookup':
                owner  => 'root',
                group  => 'root',
                mode   => '0555',
                source => 'puppet:///modules/ldap/scripts/ssh-key-ldap-lookup-python2.py',
            }
        } else {
            file { '/usr/sbin/ssh-key-ldap-lookup':
                owner  => 'root',
                group  => 'root',
                mode   => '0555',
                source => 'puppet:///modules/ldap/scripts/ssh-key-ldap-lookup.py',
            }
        }
        # sshd will only run ssh-key-ldap-lookup as the 'ssh-key-ldap-lookup' user.
        user { 'ssh-key-ldap-lookup':
            ensure => present,
            system => true,
            home   => '/nonexistent', # Since things seem to check for $HOME/.whatever unconditionally...
            shell  => '/bin/false',
        }
    }
    " }
  
            it 'should detect a single problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning' do
                expect(problems).to contain_warning(msg).on_line(8).in_column(9)
            end
        end
    end
end