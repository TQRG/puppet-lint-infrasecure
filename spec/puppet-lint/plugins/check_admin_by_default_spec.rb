require 'spec_helper'

describe 'admin_by_default' do
    let(:msg) { 'SECURITY:::ADMIN_BY_DEFAULT:::Do not make default user as admin. This violates the secure by design principle.@user=admin@' }
  
    context 'user configuration as admin' do
        let(:code) { "
    class swift::test_file (
        $password,
        $auth_server = '127.0.0.1',
        $tenant      = 'openstack',
        $user        = 'admin'
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
            expect(problems).to contain_warning(msg).on_line(6).in_column(9)
        end
    end
end