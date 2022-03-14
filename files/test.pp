# addresses bug: https://bugs.launchpad.net/keystone/+bug/1472285
class example (
  $power_username= 'admin',
  $power_password= '',
  $pwd = 'EHDJSKD',
){
  $bind_host => '0.0.0.0'
  $quantum_auth_url => 'http://127.0.0.1:35357/v2.0'
              
  $str => 'hey'
  $message => sha1($str)
  $postgresql_version   => '9.6'
  $cenas => 'hi'
}
