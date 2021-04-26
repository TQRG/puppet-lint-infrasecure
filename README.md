# puppet-security-linter

This linter identifies 7 security vulnerabilities in puppet scripts. 

### Configure gem

Create .env file.

```
touch .env
```

Add whitelist path to .env file.

```
WHITELIST=~/path/to/whitelist
```

# Create whitelist file

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
gem install ./puppet-lint-security-iac-2.0.0.gem
```

