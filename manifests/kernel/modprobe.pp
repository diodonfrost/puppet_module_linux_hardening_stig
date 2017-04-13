# Hardening modprobe.
class linux_hardening_stig::kernel::modprobe {

  # Disable modprobe loading of USB storage driver.
  file { '/etc/modprobe.d/usb-storage.conf':
    ensure  => present,
    content => 'install usb-storage /bin/true',
  }

  # Disable bluetooth.
  file { '/etc/modprobe.d/bluetooth.conf':
    ensure  => present,
    content => 'install bluetooth /bin/true',
  }

  # Direct root logins not allowed.
  file { '/etc/securetty':
    ensure  => present,
    content => '',
  }

  # Disable Ctrl-Alt-Del reboot activation.
  service { 'ctrl-alt-del.target':
    ensure => stopped,
    enable => 'mask',
  }

  # Disable kdump.
  service { 'kdump':
    ensure => stopped,
    enable => false,
  }
}