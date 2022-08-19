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

  control 'SV-230373' do
    impact 0.0
    desc "caveat", "Not applicable for this CMS ARS 5.0 overlay, since this requirement is not included in CMS ARS 5.0."
  end

  control 'SV-230484' do
    title "RHEL 8 must securely compare internal information system clocks at
    least every 24 hours with a server synchronized to an authoritative time
    source, such as the United States Naval Observatory (USNO) time servers, or a
    time server designated for the appropriate #{input('org_name')[:acronym]} network."
  end

end