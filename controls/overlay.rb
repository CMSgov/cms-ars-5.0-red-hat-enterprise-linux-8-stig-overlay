# encoding: utf-8
overlay_controls = input('overlay_controls')
system_categorization = input('system_categorization')

include_controls 'redhat-enterprise-linux-8-stig-baseline' do
  unless overlay_controls.empty?
    overlay_controls.each do |overlay_control|
      control overlay_control do
        impact 0.0
        desc "caveat", "Not applicable for this CMS ARS 5.0 overlay, since the requirement is not included in CMS ARS 5.0"
      end
    end
  end

  
  ## NIST tags updated due to changes between NIST SP 800-53 rev 4 and rev 5 (https://csrc.nist.gov/csrc/media/Publications/sp/800-53/rev-5/final/documents/sp800-53r4-to-r5-comparison-workbook.xlsx)

  ## IA-2(6) incorporates withdrawn controls IA-2(7) and IA-2(11)

  control 'SV-230273' do
    tag nist: ["IA-2 (6)"]
  end
  
  control 'SV-230274' do
    tag nist: ["IA-2 (6)"]
  end

  ## SC-45(1) incorporates withdrawn control AU-8(1)
  
  control 'SV-230484' do
    tag nist: ["SC-45 (1)"]
  end
  
  ## AC-2(3) maintains requirement to disable accounts, removed from rev 4's IA-4 e
  
  control "SV-230373" do
    tag nist: ["AC-2 (3)"]
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
    time server designated for the appropriate #{input('org_name')[:acronym]} network."
  end

end
