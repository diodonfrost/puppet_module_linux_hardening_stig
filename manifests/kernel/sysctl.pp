# Sysctl hardening.
class linux_hardening_stig::kernel::sysctl(
  String $kernel_weak_ipv4_net_sysctl  = '0',
  String $kernel_adv_ipv4_net_sysctl   = '1',
  String $kernel_ipv6_disabled         = '1',
  String $kernel_weak_ipv6_net_sysctl  = '0',
  String $kernel_adv_ipv6_net_sysctl   = '1',
  String $kernel_sysrq                 = '0',
  String $kernel_fs_suid_dumpable      = '0',
  String $kernel_kptr_restrict         = '1',
  String $kernel_dmesg_restrict        = '1',
  String $kernel_perf_event_max_rate   = '1',
  String $kernel_perf_cpu_time_max     = '1',
  String $kernel_pid_max               = '65536',
  String $kernel_perf_event_paranoid   = '2',
  String $kernel_randomize_va_space    = '2',
  String $kernel_vm_mmap_min_addr      = '65536',
  ) {

  # Sysctl ipv4 hardening.
  sysctl {
    default:
      value => $kernel_weak_ipv4_net_sysctl,
    ;
    'net.ipv4.ip_forward':
    ;
    'net.ipv4.conf.all.send_redirects':
    ;
    'net.ipv4.conf.default.send_redirects':
    ;
    'net.ipv4.conf.all.accept_source_route':
    ;
    'net.ipv4.conf.default.accept_source_route':
    ;
    'net.ipv4.conf.all.accept_redirects':
    ;
    'net.ipv4.conf.all.secure_redirects':
    ;
    'net.ipv4.conf.default.accept_redirects':
    ;
    'net.ipv4.conf.default.secure_redirects':
    ;
  }

  # Sysctl advanced ipv4 hardening.
  sysctl {
    default:
      value => $kernel_adv_ipv4_net_sysctl,
    ;
    'net.ipv4.conf.all.rp_filter':
    ;
    'net.ipv4.conf.default.rp_filter':
    ;
    'net.ipv4.conf.all.log_martians':
    ;
    'net.ipv4.tcp_rfc1337':
    ;
    'net.ipv4.icmp_ignore_bogus_error_responses':
    ;
    'net.ipv4.icmp_echo_ignore_broadcasts':
    ;
    'net.ipv4.tcp_syncookies':
    ;
  }

  # Sysctl ipv6 hardening.
  sysctl {
    default:
      value => $kernel_weak_ipv6_net_sysctl,
    ;
    'net.ipv6.conf.all.router_solicitations':
    ;
    'net.ipv6.conf.default.router_solicitations':
    ;
    'net.ipv6.conf.all.accept_ra_rtr_pref':
    ;
    'net.ipv6.conf.default.accept_ra_rtr_pref':
    ;
    'net.ipv6.conf.all.accept_ra_pinfo':
    ;
    'net.ipv6.conf.default.accept_ra_pinfo':
    ;
    'net.ipv6.conf.all.accept_ra_defrtr':
    ;
    'net.ipv6.conf.default.accept_ra_defrtr':
    ;
    'net.ipv6.conf.all.autoconf':
    ;
    'net.ipv6.conf.default.autoconf':
    ;
    'net.ipv6.conf.all.accept_redirects':
    ;
    'net.ipv6.conf.default.accept_redirects':
    ;
    'net.ipv6.conf.all.accept_source_route':
    ;
    'net.ipv6.conf.default.accept_source_route':
    ;
    'net.ipv6.conf.all.disable_ipv6':
    ;
  }

  # Other sysctl hardening rules.
  sysctl {
    'kernel.sysrq':
      value => $kernel_sysrq,
    ;
    'fs.suid_dumpable':
      value => $kernel_fs_suid_dumpable,
    ;
    'net.ipv6.conf.all.max_addresses':
      value => $kernel_adv_ipv6_net_sysctl,
    ;
    'net.ipv6.conf.default.max_addresses':
      value => $kernel_adv_ipv6_net_sysctl,
    ;
    'kernel.kptr_restrict':
      value => $kernel_kptr_restrict,
    ;
    'kernel.dmesg_restrict':
      value => $kernel_dmesg_restrict,
    ;
    'kernel.perf_event_max_sample_rate':
      value => $kernel_perf_event_max_rate,
    ;
    'kernel.perf_cpu_time_max_percent':
      value => $kernel_perf_cpu_time_max,
    ;
    'vm.mmap_min_addr':
      value => $kernel_vm_mmap_min_addr,
    ;
    'kernel.pid_max':
      value => $kernel_pid_max,
    ;
    'kernel.perf_event_paranoid':
      value => $kernel_perf_event_paranoid,
    ;
    'kernel.randomize_va_space':
      value => $kernel_randomize_va_space,
    ;
  }
}