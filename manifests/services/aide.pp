# Install and configure aide.
class linux_hardening_stig::services::aide (

) {

  # Install aide.
  package { 'aide':
    ensure => present,
    notify => Exec['/usr/sbin/aide --init'],
  }

  # Build aide Database.
  exec { '/usr/sbin/aide --init':
    path        => '/usr/local/bin/:/bin/:/usr/sbin/',
    provider    => 'shell',
    refreshonly => true,
  }

  cron { 'Configure Periodic Execution of aide':
    command => '/usr/sbin/aide --check',
    user    => 'root',
    minute  => 05,
    hour    => 4,
    require => Package['aide'],
  }
}