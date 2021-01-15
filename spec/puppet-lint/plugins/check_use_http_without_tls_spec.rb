require 'spec_helper'

describe 'use_http_without_tls' do
    let(:msg) { 'SECURITY:::HTTP:::Do not use HTTP without TLS. This may cause a man in the middle attack. Use TLS with HTTP.@http://localhost:2380@' }
  
    context 'configuration using http' do
        let(:code) { "
    $initial_advertise_peer_urls = ['http://localhost:2380']
    $initial_cluster_state = 'new'
    $initial_cluster_token = 'etcd-cluster'
    $discovery = undef
    $discovery_srv = undef
    $discovery_fallback = 'proxy'
    $discovery_proxy = undef
    $strict_reconfig_check = false
    $auto_compaction_retention = undef
    " }
  
        it 'should detect a single problem' do
            expect(problems).to have(1).problem
        end
  
        it 'should create a warning' do
            expect(problems).to contain_warning(msg).on_line(2).in_column(37)
        end
    end
end