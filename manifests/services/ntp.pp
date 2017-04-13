# Hardening ntp service
class linux_hardening_stig::services::ntp (
  $ntp_servers,

) {

  # Set multiple ntp servers.
  class { '::ntp':
    servers => $ntp_servers,
  }
}