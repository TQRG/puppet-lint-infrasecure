require 'spec_helper'

describe 'use_http_without_tls' do
    let(:msg) { '[SECURITY] HTTP without TLS (line=2, col=23) | Do not use HTTP without TLS as in http://localhost:2021. This may cause a MITM attack.' }
  
    context 'with fix disabled' do
        context 'configuration using http' do
            let(:code) { "
            $server = 'http://localhost:2021'

    apt::source { 'deb-updates':
    location          => 'http://ftp.nl.debian.org/debian/',
    release           => 'jessie-updates',
    repos             => 'main',
    include_src       => true
        }
    
    wget::fetch { 'deb-updates':
    location          => 'http://ftp.nl.debian.org/debian/',
    release           => 'jessie-updates',
    repos             => 'main',
    include_src       => true
        }

        aptly::mirror {
            'aptly':
              location => 'http://repo.aptly.info',
              release  => 'squeeze',
              key      => 'ED75B5A4483DA07C';
            'duplicity':
              location => 'http://ppa.launchpad.net/duplicity-team/ppa/ubuntu',
              release  => 'trusty',
              key      => 'AF953139C1DF9EF3476DE1D58F571BB27A86F4A2';
            'docker':
              location => 'https://download.docker.com/linux/ubuntu',
              release  => 'trusty',
              repos    => ['stable'],
              key      => '9DC858229FC7DD38854AE2D88D81803C0EBFCD88';
            'govuk-ppa-trusty':
              location => 'http://ppa.launchpad.net/gds/govuk/ubuntu',
              release  => 'trusty',
              key      => '914D5813';
            'grafana':
              location => 'https://packagecloud.io/grafana/stable/debian',
              release  => 'jessie',
              key      => '418A7F2FB0E1E6E7EABF6FE8C2E73424D59097AB';
        }

        apt::source {
      'debian':
        location => 'http://mirrors/debian/',
        release  => $::lsbdistcodename,
        repos    => $repos,
        include  => {
          src => true
        };

      'debian-updates':
        location => 'http://mirrors/debian/',
        release  => 'updates',
        repos    => $repos,
        include  => {
          src => true
        };
    }
        $package_gpg_key            = 'http://www.rabbitmq.com/rabbitmq-signing-key-public.asc'
        $elasticsearch_uri = 'http://elasticsearch6'

        $check = $puppet_metrics_dashboard::use_dashboard_ssl ? {
            true    => 'https',
            default => 'http',
          }
        
        mirrorlist     => 'http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=updates'


        $resource = 'http://cbs.centos.org/repos/nfv7-opendaylight-4-testing/$basearch/os/'
        $fedora = 'http://archives.fedoraproject.org/pub/archive/fedora/linux/releases'
        $fedora_2 = 'http://archives.fedoraproject.org/pub/archive/fedora/linux/releases'

        yumrepo{'contrib':
        descr          => 'CentOS-$releasever - Contrib',
        baseurl    => 'http://pulp.inuits.eu/pulp/repos/centos/$releasever/contrib/$basearch'
    }

        $backports_location = 'http://hello.com'

        $pwd = root
        $website = 'http://apt.postgresql.org/pub/repos/apt/'
        changes => 'set exist/xquery/builtin-modules/module[#attribute/uri = \"http://exist-db.org/xquery/xmldiff\"]/#attribute/class org.exist.xquery.modules.xmldiff.XmlDiffModule'
    " }
  
            it 'should detect a single problem' do
                expect(problems).to have(1).problem
            end
  
            it 'should create a warning' do
                expect(problems).to contain_warning(msg).on_line(2).in_column(23)
            end
        end
    end
end