# Hardening firewall
class linux_hardening_stig::network::firewall {

  class { 'firewalld':
    package        => 'firewalld',
    package_ensure => 'installed',
    service_ensure => running,
    service_enable => true,
    default_zone   => 'drop',
  }
}