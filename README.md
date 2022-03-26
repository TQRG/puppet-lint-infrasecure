# puppet-lint-infrasecure [![Gem Version](https://badge.fury.io/rb/puppet-lint-infrasecure.svg)](https://badge.fury.io/rb/puppet-lint-infrasecure)

The goal of this project is to identify potential security issues in your puppet scripts. Ten different checks/plug-ins for puppet-lint are implemented. Contributions are welcome.

#### Installation

```
gem install puppet-lint-infrasecure
```

#### Run

```
puppet-lint --json <file>
```

#### Security Plug-ins

Usage documentation is available here.

|    CWE-ID      |              Anti-Pattern              |              Example             |
|:---------------|----------------------------------------|----------------------------------|
|    `CWE-250`   | Admin by default credentials <br /> `admin_by_default` | `$user = 'admin'` <br />  `$pwd = 'admin'` |
|    `CWE-798`   | Hard-coded secrets (password, user, keys) <br /> `hardcoded_secret` | `$username = 'apmirror'` |
|    `CWE-258`   | Invalid IP address binding <br />`invalid_ip_addr_binding` | `$bind_host = '0.0.0.0'` |
|    `CWE-319`   | Use of HTTP without TLS (whitelist config) <br /> `use_http_without_tls` | `$auth_url = 'http://127.0.0.1:35357/v2.0'` |
|    `CWE-326`   | Usage of weak crypto algorithms (sha1, md5) <br /> `use_of_weak_crypto_algorithm` | `password => md5($debian_password)` |
|    `CWE-521`   | Usage of weak passwords (uses [strong_password](https://github.com/bdmac/strong_password)) <br /> `weak_password` | `$pwd = '12345'` |
|    `CWE-546`   | Suspicious comments <br /> `suspicious_comment` | `# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=538392` |
|    `CWE-829`   | Malicious dependencies (beta) <br /> `malicious_dependency` | `$postgresql_version = '8.4'` |
|    `CWE-1007`  | Homograph Attacks (e.g., [Apple](https://www.xudongz.com/blog/2017/idn-phishing/)) <br /> `cyrillic_homograph_attack`| `$source = 'https://downloads.аpаche.org/activemq/5.17.0/apache-activemq-5.17.0-bin.zip'` |

List security plug-ins:
```
puppet-lint --list-checks
```
Output should integrate the following list of plug-ins:

```
admin_by_default
cyrillic_homograph_attack
empty_password
hardcoded_secret
invalid_ip_addr_binding
malicious_dependency
suspicious_comment
use_http_without_tls
use_of_weak_crypto_algorithm
weak_password
```

A default `whitelist` is available for `use_http_without_tls`. You can set your own personalized whitelist.

1. Create `.env` file.
2. Add the whitelist path to the `.env` file.
```
WHITELIST=~/path/to/whitelist
```
3. Whitelist Schema
```
<link1>
<link2>
<link3>
```
e.g.,

```
http://apt.postgresql.org/.*
http://packages.vmware.com
http://.*.jenkins-ci.org/.*
```


#### Reporting bugs

Any bugs related with our plug-ins, please create an issue in our [issue tracker](https://github.com/TQRG/puppet-lint-infrasecure).

#### Contributions

Many other security anti-patterns may be out there, therefore feel free to contribute through a [pull request](https://github.com/TQRG/puppet-lint-infrasecure/pulls). 

