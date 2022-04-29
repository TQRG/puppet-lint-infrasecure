require 'spec_helper'

describe 'use_of_weak_crypto_algorithm' do
    let(:msg) { 'SECURITY:::MD5:::Do not use MD5 or SHA1, as they have security weakness. Use SHA-512.@sha1@' }
    
    context 'with fix disabled' do
        context 'code using unsecure algorithms' do
            let(:code) { "
    define tomcat::instance (
        $catalina_home          = undef,
        $catalina_base          = undef,
        $user                   = undef,
        $group                  = undef,
        $manage_user            = undef,
        $manage_group           = undef,
        $manage_service         = undef,
        $manage_base            = undef,
        $java_home              = undef,
        $use_jsvc               = undef,
        $use_init               = undef,
        $install_from_source    = undef,
        $source_url             = undef,
        $source_strip_first_dir = undef,
        $package_ensure         = undef,
        $package_name           = undef,
        $package_options        = undef,
    ) {
        $home_sha = sha1($_catalina_home)
        $ssl_chipers = 'HIGH:!aNULL:!MD5'
        $path = '/usr/local/go/src/crypto/sha1/sha1block_s390x'
    }
    " }
  
            it 'should detect a single problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning' do
                expect(problems).to contain_warning(msg).on_line(21).in_column(21)
            end
        end
    end
end