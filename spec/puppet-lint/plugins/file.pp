class { 'apache::mod::ssl':
  ssl_compression        => false,
  ssl_options            => [ 'StdEnvVars' ],
  ssl_cipher             => 'HIGH:MEDIUM:!aNULL:!MD5',
  ssl_protocol           => [ 'all', '-SSLv2', '-SSLv3' ],
  ssl_pass_phrase_dialog => 'builtin',
  ssl_random_seed_bytes  => '512',
}
