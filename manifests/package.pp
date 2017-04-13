# Hardening package
class linux_hardening_stig::package(

) {

  package { 'screen':
    ensure => present,
  }

}