require 'spec_helper'

describe 'admin_by_default' do
    let(:msg) { '[SECURITY][CWE-250] Admin by default (line=6, col=22) | Do not make user as admin as for $user in line 6. This can be easily exploited.' }
    
    context 'with fix disabled' do
        context 'user configuration as admin' do
            let(:code) { "
    class swift::test_file (
        $password,
        $auth_server = '127.0.0.1',
        $tenant      = 'openstack',
        $user        = 'admin'
        $admin_user      = 'admin',
    ) {
        include swift::deps
          
        file { '/tmp/swift_test_file.rb':
            mode    => '0755',
            content => template('swift/swift_keystone_test.erb'),
            tag     => 'swift-file',
        }
    }     
    " }
            it 'should detect one problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning for svnwc user config' do
                expect(problems).to contain_warning(msg).on_line(6).in_column(22)
            end
        end
    end
end