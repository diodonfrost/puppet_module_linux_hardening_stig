require 'spec_helper'
describe 'puppet_module_linux_hardening_stig' do
  context 'with default values for all parameters' do
    it { should contain_class('puppet_module_linux_hardening_stig') }
  end
end
