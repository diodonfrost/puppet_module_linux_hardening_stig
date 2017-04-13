# Hardening filesystem
class linux_hardening_stig::filesystem (
  String $filesystem_logfiles_perm  = '0600',
  Boolean $filesystem_hidden_process = true,
  ) {

  # Set permission on filelog
  file { ['/var/log/messages', '/var/log/secure', '/var/log/maillog', '/var/log/spooler', '/var/log/cron', '/var/log/boot.log']:
    mode => $filesystem_logfiles_perm,
  }

  # Hiding processes from other users
  file_line { 'insert/update fstab configuation block in /etc/fstab for hidden process':
    ensure => bool2str($filesystem_hidden_process, 'present', 'absent'),
    path   => '/etc/fstab',
    match  => '^proc',
    line   => 'proc /proc proc defaults,hidepid=2 0 0',
    notify => Exec['remount proc'],
  }

  # Remount proc when fstab proc is modified
  exec { 'remount proc':
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin',],
    command     => 'mount -o remount,rw,hidepid=2 /proc',
    refreshonly => true,
  }

  file_line { 'Disable grub recovery':
    ensure => present,
    path   => '/etc/default/grub',
    match  => '^GRUB_DISABLE_RECOVERY=',
    line   => 'GRUB_DISABLE_RECOVERY="true"',
    notify => Exec['update system boot'],
  }

  exec { 'update system boot':
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin',],
    command     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
    refreshonly => true,
  }
}
