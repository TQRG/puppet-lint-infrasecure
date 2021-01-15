# addresses bug: https://bugs.launchpad.net/keystone/+bug/1472285
class example (
  $power_username= 'admin',
  $power_password= 'admin'
){
  $bind_host = '0.0.0.0'
  
  $quantum_auth_url = 'http://127.0.0.1:35357/v2.0'
  case $::osfamily
    'CentOS': {
      user {
        name => 'admin-user',
        password => $power_password,
      }
    }
    'RedHat': {
      user {
        name => 'admin-user',
        password => ''
      }
    }
    'Debian': {
      user {
        name => 'admin-user',
        password => ht_md5($power_password)
      }
    }
    default: {
      user {
        name => 'admin-user',
        password => $power_password
      }
    }
  }
}
