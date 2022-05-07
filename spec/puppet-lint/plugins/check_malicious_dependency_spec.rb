require 'spec_helper'

describe 'malicious_dependency' do
    let(:msg) {'[SECURITY][CWE-829] Malicious Dependency (line=10, col=40) | This software is using a third-party library/software (postgresql v9.4) affected by known CVEs (CVE-2017-12172, CVE-2017-15098, CVE-2017-7484, CVE-2017-7485, CVE-2017-7486, CVE-2017-7546, CVE-2017-7547, CVE-2017-7548, CVE-2016-0766, CVE-2016-0773, CVE-2016-5423, CVE-2016-5424).'}
    
    context 'with fix disabled' do
        context 'software uses malicious dependencies' do
            let(:code) { "
                postgresql::server::pg_hba_rule { 'allow application network to access app database':
                    description        => 'Open up postgresql for access from 200.1.2.0/24',
                    type               => 'host',
                    database           => 'app',
                    user               => 'app',
                    address            => '200.1.2.0/24',
                    auth_method        => 'md5',
                    target             => '/path/to/pg_hba.conf',
                    postgresql_version => '9.4',
                  }
                  
                class { 'test':
                    openstack_version => '10'
                }

                class { 'postgresql::globals':
                    manage_package_repo => true,
                    version             => '9.2',
                }
            " }
  
            it 'should detect a single problem' do
                expect(problems).to have(3).problem
            end
  
            it 'should create a warning' do
                expect(problems).to contain_warning(msg).on_line(10).in_column(40)
            end
        end
    end
end