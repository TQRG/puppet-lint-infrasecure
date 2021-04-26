# puppet-lint-security-iac

⚠️  This is still work in progress!

This linter identifies 9 security vulnerabilities in Puppet scripts. 

- Admin By Default Credentials
- Empty Passwords
- Hard-Coded Secrets (password, user, keys)
- Invalid IP Address Binding
- Use of HTTP without TLS
- Usage of Weak Crypto Algorithms (e.g., sha1 and md5)
- Suspicious Comments
- Malicious Dependencies
- Homograph Attacks (e.g., [Apple](https://www.xudongz.com/blog/2017/idn-phishing/))

### Configure gem

Create .env file.

```
touch .env
```

Add whitelist path to .env file.

```
WHITELIST=~/path/to/whitelist
```

### Create whitelist file

A whitelist by default is provided. You can build your own if you want by following this structure:

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
gem build puppet_lint_security_iac.gemspec
```

### Installation 

```
gem install ./puppet-lint-security-iac-1.0.0.gem
```