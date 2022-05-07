require 'spec_helper'

describe 'invalid_ip_addr_binding' do
    let(:msg) {'[SECURITY][CWE-284] Invalid IP Address Binding (line=4, col=30) | Don\'t bind your host to 0.0.0.0. This config allows connections from every possible network. Restrict your available IPs.' }
    
    context 'with fix disabled' do
        context 'invalid ip adress binding configuration' do
            let(:code) { "
    class centos_cloud::controller::nova (
        $allowed_hosts     = '172.22.6.%',
        $bind_host         = '0.0.0.0',
        $controller        = 'controller.openstack.ci.centos.org',
        $memcached_servers = ['127.0.0.1:11211'],
        $password          = 'nova',
        $password_api      = 'nova_api',
        $rabbit_port       = '5672',
        $user              = 'nova',
        $user_api          = 'nova_api',
        $neutron_password  = 'neutron',
        $workers           = '8',
        $threads           = '1'
    ) { 
        rabbitmq_user { $user:
            admin    => true,
            provider => 'rabbitmqctl',
            require  => Class['::rabbitmq']
        }

        if $bind_ip == '0.0.0.0' {
            $bind_ip_real = '127.0.0.1'
          } else {
            $bind_ip_real = $bind_ip
          }        
    }
    " }
  
            it 'should detect a single problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning' do
                expect(problems).to contain_warning(msg).on_line(4).in_column(30)
            end
        end
    end
end