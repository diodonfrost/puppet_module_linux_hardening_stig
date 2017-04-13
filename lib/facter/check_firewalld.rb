require 'facter'
Facter.add(:firewalld) do 
  setcode do
  	Facter::Util::Resolution.exec("systemctl status firewalld")
  end
end
