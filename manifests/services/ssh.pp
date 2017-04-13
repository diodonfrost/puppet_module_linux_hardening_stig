# Hardening ssh service.
class linux_hardening_stig::services::ssh (
    Boolean $ssh_banner,
    Hash[String, Any] $ssh_settings,
) {

  package { 'openssh-server':
    ensure   => present,
  }

  service { 'sshd':
    ensure  => running,
    enable  => true,
    require => Package['openssh-server'],
  }

  # Set ssh login banner
  file { 'Set banner':
    ensure  => bool2str($ssh_banner, 'present', 'absent'),
    path    => '/etc/issue',
    source  => 'puppet:///modules/linux_hardening/sshd/issue.client',
    require => Package['openssh-server'],
  }

  # Configure ssh service with hardening params.
  $ssh_settings.each |$key, $val| {
    ini_setting { "Hardening ssh ${key}":
      ensure            => present,
      key_val_separator => ' ',
      path              => '/etc/ssh/sshd_config',
      setting           => $key,
      value             => $val,
      notify            => Service['sshd'],
    }
  }
}