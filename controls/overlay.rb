# encoding: utf-8
overlay_controls = input('overlay_controls')
system_categorization = input('system_categorization')

include_controls 'redhat-enterprise-linux-8-stig-baseline' do
  unless overlay_controls.empty? # Test with !oc.any?
    overlay_controls.each do |overlay_control|
      control overlay_control do
        impact 0.0
        desc "caveat", "Not applicable for this CMS ARS 5.0 overlay, since the related security control is not included in CMS ARS 5.0 for the system categorization of #{system_categorization}"
      end
    end
  end

  control 'SV-230229' do
    desc 'fix', "Configure RHEL 8, for PKI-based authentication, to validate certificates by
    constructing a certification path (which includes status information) to an
    accepted trust anchor.
    
        Obtain a valid copy of the #{input('org_name')[:acronym]} root CA file from the PKI CA certificate
    bundle and copy the #{input('org_name')[:acronym]}_PKE_CA_chain.pem into the following file:
    
        /etc/sssd/pki/sssd_auth_ca_db.pem"
  end

  control 'SV-230484' do
    title "RHEL 8 must securely compare internal information system clocks at
    least every 24 hours with a server synchronized to an authoritative time
    source, such as the United States Naval Observatory (USNO) time servers, or a
    time server designated for the appropriate #{ input('org_name')[:acronym] } network."
  end

end
#  control 'SV-230483' do
#    title "RHEL 8 must take action when allocated audit record storage volume
#    reaches 80 percent of the repository maximum audit record storage capacity."
#  end
#
#  control 'SV-230483' do
#    desc 'check', "Verify RHEL 8 takes action when allocated audit record storage volume
#    reaches 80 percent of the repository maximum audit record storage capacity with
#    the following commands:
#    
#        $ sudo grep -w space_left /etc/audit/auditd.conf
#    
#        space_left = 20%
#    
#        If the value of the \"space_left\" keyword is not set to \"20%\" or if the
#    line is commented out, ask the System Administrator to indicate how the system
#    is providing real-time alerts to the SA and ISSO.
#    
#        If there is no evidence that real-time alerts are configured on the system,
#    this is a finding."
#  end
#
#  control 'SV-230483' do
#    desc 'fix', "Configure the operating system to initiate an action to notify the SA and
#    ISSO (at a minimum) when allocated audit record storage volume reaches 80
#    percent of the repository maximum audit record storage capacity by
#    adding/modifying the following line in the /etc/audit/auditd.conf file.
#    
#        space_left = 20%
#    
#        Note: Option names and values in the auditd.conf file are case insensitive."
#  end