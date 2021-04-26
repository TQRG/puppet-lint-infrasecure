require 'spec_helper'

describe 'empty_password' do
    let(:msg) { '[SECURITY] Empty Password (line=12, col=32) | Do not keep the password field empty as for $password in line 12. Use kms/heira/vault instead.' }
    
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
        $password            = '',
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
        

        $real_htpasswd_file = $htpasswd_file ? {
            ''      => '${apache::params::config_dir}/htpasswd'
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
                expect(problems).to contain_warning(msg).on_line(12).in_column(32)
            end
        end
    end
end