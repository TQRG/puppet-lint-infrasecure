require 'spec_helper'

describe 'hardcoded_secret_password' do
    let(:msg) { '[SECURITY][CWE-259] Hard Coded Password (line=10, col=36) | Do not keep secrets on your scripts as for $username_password = apmirror in line 10. Store secrets in a vault instead.' }
    
    context 'with fix disabled' do
        context 'code contains hard coded usernames' do
            let(:code) { "
    class apmirror (
        $uid            = 508,
        $gid            = 508,
        $group_present  = 'present',
        $groupname      = 'apmirror',
        $groups         = [],
        $service_ensure = 'running',
        $cert          = '/bin/bash',
        $username_password       = 'apmirror',
        $packages       = ['libwww-perl', 'libnet-dns-perl'],
    ){
        package { $packages:
            ensure => present,
        }

        $cert_generation_class      = '::puppet::puppetserver::generate_cert'

        $pwd = undef
        $pwd = $cert
        $pwd = 'pe-puppet'
          
        user { $username:
            ensure     => $user_present,
            name       => $username,
            home       => '/home/${username}',
            shell      => $shell,
            uid        => $uid,
            gid        => $groupname,
            groups     => $groups,
            managehome => true,
            require    => [ Group[$groupname], Group[$apbackup::username] ],
        }

    }
    " }
  
            it 'should detect one problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning for username hard coded config' do
                expect(problems).to contain_warning(msg).on_line(10).in_column(36)
            end
        end
    end
end