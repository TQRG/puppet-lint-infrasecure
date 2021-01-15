require 'spec_helper'

describe 'empty_password' do
    let(:msg) { 'SECURITY:::EMPTY_PASSWORD:::Do not keep password field empty. This may help an attacker to attack. You can use hiera to avoid this issue.@pass=@' }
    
    context 'with fix disabled' do
        context 'code configuration using empty passwords' do
            let(:code) { "
    define znc::user (
        $ensure          = 'present',
        $realname        = undef,
        $admin           = false,
        $buffer          = 500,
        $keepbuffer      = true,
        $server          = 'irc.freenode.net',
        $port            = 6667,
        $ssl             = false,
        $quitmsg         = 'quit',
        $pass            = '',
        $channels        = undef,
        $network         = undef,
        $maxnetworks     = 1,
        $loadmodules     = undef,) {
        if ! defined(Class['znc']) {
            fail('You must include znc base class before using any user defined resources')
        }
        include znc::params
          
        File {
            owner => $::znc::params::zc_user,
            group => $::znc::params::zc_group,
            mode  => '0600',
        }
          
        Exec {
            path => '/bin:/sbin:/usr/bin:/usr/sbin', 
        }
    }      
    " }
  
            it 'should detect one problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning for svnwc user config' do
                expect(problems).to contain_warning(msg).on_line(12).in_column(9)
            end
        end
    end
end