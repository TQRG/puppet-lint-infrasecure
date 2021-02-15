# puppet-security-linter

This linter identifies 7 security code smells in infrasctruture as code scripts implemented in Puppet. 

### Install Gems

```
bundle install
```

### Run Tests

```
bundle exec rake
```

### Build Gem

```
gem build puppet_security_linter.gemspec
```

### Installation 

```
sudo gem install ./puppet-security-linter-V.0.0.gem
```
where v is the version. version = {1,2}

### Run Example

```
puppet-lint files/test.pp
```

Ouput should contain the following warnings:
```
WARNING: SECURITY:::ADMIN_BY_DEFAULT:::Do not make default user as admin. This violates the secure by design principle.@power_username=admin@ on line 3
WARNING: SECURITY:::HTTP:::Do not use HTTP without TLS. This may cause a man in the middle attack. Use TLS with HTTP.@http://127.0.0.1:35357/v2.0@ on line 8
WARNING: SECURITY:::SUSPICOUS_COMMENTS:::Do not expose sensitive information@# addresses bug: https://bugs.launchpad.net/keystone/+bug/1472285@ on line 1
WARNING: SECURITY:::HARD_CODED_SECRET_V1:::Do not hard code secrets. This may help an attacker to attack the system. You can use hiera to avoid this issue.@power_username=admin@ on line 3
WARNING: SECURITY:::HARD_CODED_SECRET_V1:::Do not hard code secrets. This may help an attacker to attack the system. You can use hiera to avoid this issue.@power_password=admin@ on line 4
WARNING: SECURITY:::HARD_CODED_SECRET_V1:::Do not hard code secrets. This may help an attacker to attack the system. You can use hiera to avoid this issue.@password=ht_md5@ on line 25
WARNING: SECURITY:::MD5:::Do not use MD5 or SHA1, as they have security weakness. Use SHA-512.@ht_md5@ on line 25
WARNING: SECURITY:::BINDING_TO_ALL:::Do not bind to 0.0.0.0. This may cause a DDOS attack. Restrict your available IPs. on line 6
WARNING: SECURITY:::EMPTY_PASSWORD:::Do not keep password field empty. This may help an attacker to attack. You can use hiera to avoid this issue.@password=@ on line 19
```