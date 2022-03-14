# puppet-lint-security-iac

Hey you! 👋  Do you have experience in Puppet or similar tools (e.g., Ansible, Terraform, Chef) and appreciate security? Then, we would very much appreciate your colaboration. 😊 ▶️   [https://puppet-study.herokuapp.com/](https://puppet-study.herokuapp.com/)

⚠️  This is still work in progress! 

This linter identifies 9 security vulnerabilities in Puppet scripts. 

- Admin By Default Credentials
- Empty Passwords
- Hard-Coded Secrets (password, user, keys)
- Invalid IP Address Binding
- Use of HTTP without TLS
- Usage of Weak Crypto Algorithms (e.g., sha1 and md5)
- Usage of Weak Passwords ([strong_password](https://github.com/bdmac/strong_password) gem to validate if weak)
- Suspicious Comments
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
