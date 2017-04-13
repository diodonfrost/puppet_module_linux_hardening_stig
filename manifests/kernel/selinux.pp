# Configure SELinux
class linux_hardening_stig::kernel::selinux (
  String $selinux_mode,
  Boolean $selinux_boolean_execstack,
  Boolean $selinux_boolean_execheap,
  Boolean $selinux_boolean_virt_use_usb,
  Boolean $selinux_boolean_deny_ptrace,
) {

  # Set SELinux mode
  file_line { 'Selinux config':
    ensure => present,
    path   => '/etc/selinux/config',
    match  => '^SELINUX=',
    line   => "SELINUX=${selinux_mode}",
    }

  # Set SELinux boolean
  if $::selinux {
    selboolean {
      default:
        persistent => true,
      ;
      # Deny selinuxuser to execstack
      'Set boolean execstack':
        name  => 'selinuxuser_execstack',
        value => bool2str($selinux_boolean_execstack, 'on', 'off'),
      ;
      # Deny selinuxuser to execstack
      'Set boolean execheap':
        name  => 'selinuxuser_execheap',
        value => bool2str($selinux_boolean_execheap, 'on', 'off'),
      ;
      # Deny virt to use usb
      'Set boolean virt_use_usb':
        name  => virt_use_usb,
        value => bool2str($selinux_boolean_virt_use_usb, 'on', 'off'),
      ;
      # Deny ptrace
      'Set boolean deny_ptrace':
        name  => deny_ptrace,
        value => bool2str($selinux_boolean_deny_ptrace, 'on', 'off'),
      ;
    }
  }
}

