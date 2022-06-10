# encoding: utf-8

(pseudocode, sorry:)
if input(baseline) = low then 

na_syscat = ["SV-230240", "SV-230241", "SV-230244"]
input('difok', value: 6, profile: redhat-enterprise-linux-8-stig-baseline)

if input(baseline) = moderate then 

na_syscat = ["SV-230240", "SV-230241"]
input('difok', value: 6, profile: redhat-enterprise-linux-8-stig-baseline)

if input(baseline) = high then 

na_syscat = []
input('difok', value: 12, profile: redhat-enterprise-linux-8-stig-baseline)


include_controls "redhat-enterprise-linux-8-stig-baseline" do

  control 'SV-230239' do
    desc  "Unapproved mechanisms that are used for authentication to the
  cryptographic module are not verified and therefore cannot be relied upon to
  provide confidentiality or integrity, and CMS data may be compromised.

      RHEL 8 systems utilizing encryption are required to use FIPS-compliant
  mechanisms for authenticating to cryptographic modules.

      Currently, Kerberos does not utilize FIPS 140-2 cryptography.

      FIPS 140-2 is the current standard for validating that mechanisms used to
  access cryptographic modules utilize authentication that meets CMS
  requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
  general-purpose computing system.
    "
  end

  na_syscat.each do |a_control|
	  control a_control do
		impact 0.0
		desc 'caveat', 'This is Not Applicable since the related security control is not applied to this system categorization in CMS ARS 5.0'
	  end
  end
  
#  control "SV-230240" do
#    impact 0.0
#    desc 'caveat', 'This is Not Applicable since the related security control (SC-3) is not applied to this system categorization in CMS ARS 5.0'
#  end

#  control "SV-230241" do
#    impact 0.0
#    desc 'caveat', 'This is Not Applicable since the related security control (SC-3) is not applied to this system categorization in CMS ARS 5.0'
#  end

#  control 'SV-230244' do
#    impact 0.0
#    desc 'caveat', 'This is Not Applicable since the related security control (SC-10) is not applied to this system categorization in CMS ARS 3.1'
#  end
  
  control 'SV-230363' do
    title "RHEL 8 must require the change of at least #{difok} characters when passwords
  are changed."
    desc  'check', "
      Verify the value of the \"difok\" option in
  \"/etc/security/pwquality.conf\" with the following command:

      $ sudo grep difok /etc/security/pwquality.conf

      difok = #{difok}

      If the value of \"difok\" is set to less than \"#{difok}\" or is commented out,
  this is a finding.
    "
    desc 'fix', "
      Configure the operating system to require the change of at least six of
  the total number of characters when passwords are changed by setting the
  \"difok\" option.

      Add the following line to \"/etc/security/pwquality.conf\" (or modify the
  line to have the required value):

      difok = #{difok}
    "
  end


end
