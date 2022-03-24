# puppet-lint-infrasecure

Security plug-ins:

- Admin By Default Credentials
- Empty Passwords
- Hard-Coded Secrets (password, user, keys)
- Invalid IP Address Binding
- Use of HTTP without TLS
- Usage of Weak Crypto Algorithms (e.g., sha1 and md5)
- Usage of Weak Passwords ([strong_password](https://github.com/bdmac/strong_password) gem to validate if weak)
- Suspicious Comments
- Malicious Dependencies (for 33 software packages available through [forge](https://forge.puppet.com/))
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

A whitelist by default is provided. But you can build your own if you want by following the structure below:

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
