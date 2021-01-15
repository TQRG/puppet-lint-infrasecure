require 'spec_helper'

describe 'invalid_ip_addr_binding' do
    let(:msg) { 'SECURITY:::BINDING_TO_ALL:::Do not bind to 0.0.0.0. This may cause a DDOS attack. Restrict your available IPs.' }
  
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
            password => $password,
            provider => 'rabbitmqctl',
            require  => Class['::rabbitmq']
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