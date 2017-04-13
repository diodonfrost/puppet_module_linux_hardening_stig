# Data for old puppet agent when it don't user local hiera module.
class linux_hardening_stig (
  # SELinux config
  $selinux_mode                  = 'enforcing',
  $selinux_boolean_execstack     = false,
  $selinux_boolean_execheap      = false,
  $selinux_boolean_virt_use_usb  = false,
  $selinux_boolean_deny_ptrace   = true,

  # Audit config
  $audit_access                  = true,
  $audit_actions                 = true,
  $audit_networkconfig           = true,
  $audit_usergroup               = true,
  $audit_time                    = true,
  $audit_delete                  = true,
  $audit_export                  = true,
  $audit_immutable               = true,
  $audit_logins                  = true,
  $audit_mac_policy              = true,
  $audit_modules                 = true,
  $audit_perm_mod                = true,
  $audit_privileged              = true,
  $audit_session                 = true,
  $audit_time_change             = true,
  $audit_admin_action_low_disk   = true,
  $audit_action_low_disk         = true,
  $audit_flush_priority          = true,
  $audit_syslog                  = false,

  # Filesystem config hardening
  $filesystem_logfiles_perm      = '0600',
  $filesystem_hidden_process     = true,

  # Linux sysctl kernel hardening
  $kernel_weak_ipv4_net_sysctl   = '0',
  $kernel_adv_ipv4_net_sysctl    = '1',
  $kernel_ipv6_disabled          = '1',
  $kernel_weak_ipv6_net_sysctl   = '0',
  $kernel_adv_ipv6_net_sysctl    = '1',
  $kernel_sysrq                  = '0',
  $kernel_fs_suid_dumpable       = '0',
  $kernel_kptr_restrict          = '1',
  $kernel_dmesg_restrict         = '1',
  $kernel_perf_event_max_rate    = '1',
  $kernel_perf_cpu_time_max      = '1',
  $kernel_pid_max                = '65536',
  $kernel_perf_event_paranoid    = '2',
  $kernel_randomize_va_space     = '2',
  $kernel_vm_mmap_min_addr       = '65536',

  # Package for hardening system
  $ntp_servers           = ['0.rhel.pool.ntp.org', '1.rhel.pool.ntp.org', '2.rhel.pool.ntp.org', '3.rhel.pool.ntp.org'],

  # Hardening PAM
  $pam_pwquality_settings        = { 'maxrepeat'      => '2',
                                     'dcredit'        => '-1',
                                     'minlen'         => '15',
                                     'ucredit'        => '-1',
                                     'ocredit'        => '-1',
                                     'lcredit'        => '-1',
                                     'difok'          => '5',
                                     'maxclassrepeat' => '2',
                                     'minclass'       => '4' },

  $pam_login_defs                = { 'PASS_MAX_DAYS'  => '60',
                                     'PASS_MIN_DAYS'  => '1',
                                     'ENCRYPT_METHOD' => 'SHA512', },

  # Hardening sshd
  $ssh_banner                    = true,
  Hash[String, Any]$ssh_settings = { 'Banner'                 => '/etc/issue',
                                     'Ciphers'                => 'aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc',
                                     'ClientAliveCountMax'    => '0',
                                     'ClientAliveInterval'    => '900',
                                     'Compression'            => 'no',
                                     'GSSAPIAuthentication'   => 'no',
                                     'KerberosAuthentication' => 'no',
                                     'MACs'                   => 'hmac-sha2-512,hmac-sha2-256,hmac-sha1',
                                     'PermitEmptyPasswords'   => 'no',
                                     'PermitUserEnvironment'  => 'no',
                                     'PermitRootLogin'        => 'no',
                                     'Protocol'               => '2',
                                     'StrictModes'            => 'yes',
                                     'UsePrivilegeSeparation' => 'yes',
                                     'X11Forwarding'          => 'yes', },

) {

  class { 'linux_hardening_stig::audit':
    audit_access                => $audit_access ,
    audit_actions               => $audit_actions,
    audit_networkconfig         => $audit_networkconfig ,
    audit_usergroup             => $audit_usergroup,
    audit_time                  => $audit_time,
    audit_delete                => $audit_delete,
    audit_export                => $audit_export,
    audit_immutable             => $audit_immutable,
    audit_logins                => $audit_logins,
    audit_mac_policy            => $audit_mac_policy,
    audit_modules               => $audit_modules,
    audit_perm_mod              => $audit_perm_mod,
    audit_privileged            => $audit_privileged,
    audit_session               => $audit_session,
    audit_time_change           => $audit_time_change,
    audit_admin_action_low_disk => $audit_admin_action_low_disk,
    audit_action_low_disk       => $audit_action_low_disk,
    audit_flush_priority        => $audit_flush_priority,
    audit_syslog                => $audit_syslog,
  }

  class { 'linux_hardening_stig::filesystem':
    filesystem_logfiles_perm  => $filesystem_logfiles_perm,
    filesystem_hidden_process => $filesystem_hidden_process,
  }

  class { 'linux_hardening_stig::kernel::sysctl':
    kernel_weak_ipv4_net_sysctl => $kernel_weak_ipv4_net_sysctl,
    kernel_adv_ipv4_net_sysctl  => $kernel_adv_ipv4_net_sysctl,
    kernel_ipv6_disabled        => $kernel_ipv6_disabled,
    kernel_weak_ipv6_net_sysctl => $kernel_weak_ipv6_net_sysctl,
    kernel_adv_ipv6_net_sysctl  => $kernel_adv_ipv6_net_sysctl,
    kernel_sysrq                => $kernel_sysrq,
    kernel_fs_suid_dumpable     => $kernel_fs_suid_dumpable,
    kernel_kptr_restrict        => $kernel_kptr_restrict,
    kernel_dmesg_restrict       => $kernel_dmesg_restrict,
    kernel_perf_event_max_rate  => $kernel_perf_event_max_rate,
    kernel_perf_cpu_time_max    => $kernel_perf_cpu_time_max,
    kernel_pid_max              => $kernel_pid_max,
    kernel_perf_event_paranoid  => $kernel_perf_event_paranoid,
    kernel_randomize_va_space   => $kernel_randomize_va_space,
    kernel_vm_mmap_min_addr     => $kernel_vm_mmap_min_addr,
  }

  class { 'linux_hardening_stig::kernel::selinux':
    selinux_mode                 => $selinux_mode,
    selinux_boolean_execstack    => $selinux_boolean_execstack,
    selinux_boolean_execheap     => $selinux_boolean_execheap,
    selinux_boolean_virt_use_usb => $selinux_boolean_virt_use_usb,
    selinux_boolean_deny_ptrace  => $selinux_boolean_deny_ptrace,
  }

  class { 'linux_hardening_stig::kernel::modprobe':}

  class { 'linux_hardening_stig::services::ntp':
    ntp_servers => $ntp_servers,
  }

  class { 'linux_hardening_stig::pam':
    pam_pwquality_settings => $pam_pwquality_settings,
    pam_login_defs         => $pam_login_defs,
  }

  class { 'linux_hardening_stig::services::ssh':
    ssh_banner   => $ssh_banner,
    ssh_settings => $ssh_settings,
  }

  class { 'linux_hardening_stig::services::aide':}

  class { 'linux_hardening_stig::package':}

  class { 'linux_hardening_stig::network::firewall':}

}