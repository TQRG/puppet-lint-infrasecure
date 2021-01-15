require 'spec_helper'

describe 'hardcode_secret' do
    let(:msg) { 'SECURITY:::HARD_CODED_SECRET_V1:::Do not hard code secrets. This may help an attacker to attack the system. You can use hiera to avoid this issue.@username=apmirror@' }
  
    context 'code contains hard coded usernames' do
        let(:code) { "
    class apmirror (
        $uid            = 508,
        $gid            = 508,
        $group_present  = 'present',
        $groupname      = 'apmirror',
        $groups         = [],
        $service_ensure = 'running',
        $shell          = '/bin/bash',
        $username       = 'apmirror',
        $packages       = ['libwww-perl', 'libnet-dns-perl'],
    ){
        package { $packages:
            ensure => present,
        }
          
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
            expect(problems).to contain_warning(msg).on_line(10).in_column(9)
        end
    end
end