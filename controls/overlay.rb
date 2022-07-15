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

  control 'SV-230331' do
    desc 'fix', "If a temporary account must be created configure the system to terminate
    the account after a 24 hour time period with the following command to set an
    expiration date on it. Substitute \"system_account_name\" with the account to
    be created.
        
        $ sudo chage -E `date -d \"+1 days\" +%Y-%m-%d` system_account_name"

    temporary_accounts = input('temporary_accounts'
    if temporary_accounts.empty?
      describe 'Temporary accounts' do
        subject { temporary_accounts }
        it { should be_empty }
      end
    else
      temporary_accounts.each do |acct|
        describe user(acct.to_s) do
          its('maxdays') { should cmp <= 1 }
          its('maxdays') { should cmp > 0 }
        end
      end
    end
end

control 'SV-230374' do
  desc 'fix', "If an emergency account must be created, configure the system to terminate
  the account after 24 hours with the following command to set an expiration date
  for the account. Substitute \"system_account_name\" with the account to be
  created.
  
      $ sudo chage -E `date -d \"+1 days\" +%Y-%m-%d` system_account_name
  
      The automatic expiration or disabling time period may be extended as needed
  until the crisis is resolved."

  temporary_accounts = input('temporary_accounts')

  if temporary_accounts.empty?
    describe 'Temporary accounts' do
      subject { temporary_accounts }
      it { should be_empty }
    end
  else
    temporary_accounts.each do |acct|
      describe user(acct.to_s) do
        its('maxdays') { should cmp <= 3 }
        its('maxdays') { should cmp > 0 }
      end
    end
  end
end

control 'SV-230484' do
  title, "RHEL 8 must securely compare internal information system clocks at
  least every 24 hours with a server synchronized to an authoritative time
  source, such as the United States Naval Observatory (USNO) time servers, or a
  time server designated for the appropriate #{input('org_name')[:acronym]} network."
end

  control 'SV-230332' do
      title, "RHEL 8 must automatically lock an account when five unsuccessful
      logon attempts occur."

      desc 'check', "Check that the system locks an account after five unsuccessful logon
      attempts with the following commands:

          Note: If the System Administrator demonstrates the use of an approved
      centralized account management method that locks an account after five
      unsuccessful logon attempts within a period of 120 minutes, this requirement is
      not applicable.

          Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
      RHEL version 8.2 or newer, this check is not applicable. 

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"deny\" option is not set to \"5\" or less (but not \"0\") on the
      \"preauth\" line with the \"pam_faillock.so\" module, or is missing from this
      line, this is a finding.

          If any line referencing the \"pam_faillock.so\" module is commented out,
      this is a finding.

          $ sudo grep pam_faillock.so /etc/pam.d/system-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"deny\" option is not set to \"5\" or less (but not \"0\") on the
      \"preauth\" line with the \"pam_faillock.so\" module, or is missing from this
      line, this is a finding.

          If any line referencing the \"pam_faillock.so\" module is commented out,
      this is a finding."

      desc 'fix', "Configure the operating system to lock an account when five unsuccessful
      logon attempts occur.

          Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
      \"/etc/pam.d/password-auth\" files to match the following lines:

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          The \"sssd\" service must be restarted for the changes to take effect. To
      restart the \"sssd\" service, run the following command:

          $ sudo systemctl restart sssd.service"
  end

  control 'SV-230333' do
      title, "RHEL 8 must automatically lock an account when five unsuccessful
      logon attempts occur."

      desc 'check', "Note: This check applies to RHEL versions 8.2 or newer, if the system is
      RHEL version 8.0 or 8.1, this check is not applicable.

          Verify the \"/etc/security/faillock.conf\" file is configured to lock an
      account after five unsuccessful logon attempts:

          $ sudo grep 'deny =' /etc/security/faillock.conf

          deny = 5

          If the \"deny\" option is not set to \"5\" or less (but not \"0\"), is
      missing or commented out, this is a finding."

      desc 'fix', "Configure the operating system to lock an account when five unsuccessful
      logon attempts occur.

          Add/Modify the \"/etc/security/faillock.conf\" file to match the following
      line:

          deny = 5" 
  end

  control 'SV-230334' do
      title, "RHEL 8 must automatically lock an account when five unsuccessful
      logon attempts occur during a 120-minute time period."

      desc 'check', "Check that the system locks an account after five unsuccessful logon
      attempts with the following commands:

          Note: If the System Administrator demonstrates the use of an approved
      centralized account management method that locks an account after three
      unsuccessful logon attempts within a period of 120 minutes, this requirement is
      not applicable.

          Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
      RHEL version 8.2 or newer, this check is not applicable.

          $ sudo grep pam_faillock.so /etc/pam.d/password-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"deny\" option is not set to \"5\" or less (but not \"0\") on the
      \"preauth\" line with the \"pam_faillock.so\" module, or is missing from this
      line, this is a finding.

          If any line referencing the \"pam_faillock.so\" module is commented out,
      this is a finding.

          $ sudo grep pam_faillock.so /etc/pam.d/system-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"deny\" option is not set to \"5\" or less (but not \"0\") on the
      \"preauth\" line with the \"pam_faillock.so\" module, or is missing from this
      line, this is a finding.

          If any line referencing the \"pam_faillock.so\" module is commented out,
      this is a finding."

      desc 'fix', "Configure the operating system to lock an account when five unsuccessful
      logon attempts occur.

          Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
      \"/etc/pam.d/password-auth\" files to match the following lines:

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          The \"sssd\" service must be restarted for the changes to take effect. To
      restart the \"sssd\" service, run the following command:

          $ sudo systemctl restart sssd.service"
  end

  control 'SV-230335' do
      title, "RHEL 8 must automatically lock an account when five unsuccessful
      logon attempts occur during a 120-minute time period."

      desc 'check', "Note: This check applies to RHEL versions 8.2 or newer, if the system is
      RHEL version 8.0 or 8.1, this check is not applicable.

          Verify the \"/etc/security/faillock.conf\" file is configured to lock an
      account after three unsuccessful logon attempts within 120 minutes:

          $ sudo grep 'fail_interval =' /etc/security/faillock.conf

          fail_interval = 900

          If the \"fail_interval\" option is not set to \"900\" or more, is missing
      or commented out, this is a finding."

      desc 'fix', "Configure the operating system to lock an account when five unsuccessful
      logon attempts occur in 120 minutes.

          Add/Modify the \"/etc/security/faillock.conf\" file to match the following
      line:

          fail_interval = 900"
  end

  control 'SV-230336' do
      title, "RHEL 8 must automatically lock an account until the locked account is
      released by an administrator when five unsuccessful logon attempts occur
      during a 120-minute time period."

      desc 'check', "Check that the system locks an account after five unsuccessful logon
      attempts within a period of 120 minutes until released by an administrator with
      the following commands:

          Note: If the System Administrator demonstrates the use of an approved
      centralized account management method that locks an account after five
      unsuccessful logon attempts within a period of 120 minutes, this requirement is
      not applicable.

          Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
      RHEL version 8.2 or newer, this check is not applicable.

          $ sudo grep pam_faillock.so /etc/pam.d/password-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"unlock_time\" option is not set to \"0\" on the \"preauth\" and
      \"authfail\" lines with the \"pam_faillock.so\" module, or is missing from
      these lines, this is a finding.

          $ sudo grep pam_faillock.so /etc/pam.d/system-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=3 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"unlock_time\" option is not set to \"0\" on the \"preauth\" and
      \"authfail\" lines with the \"pam_faillock.so\" module, or is missing from
      these lines, this is a finding."
  end

  control 'SV-230337' do
      title, "RHEL 8 must automatically lock an account until the locked account is
      released by an administrator when five unsuccessful logon attempts occur
      during a 120-minute time period."

      desc 'fix', "Configure the operating system to lock an account until released by an
      administrator when five unsuccessful logon attempts occur in 120 minutes.

          Add/Modify the \"/etc/security/faillock.conf\" file to match the following
      line:

          unlock_time = 0"
  end

  control 'SV-230338' do
      desc 'check', "Check that the faillock directory contents persists after a reboot with the
      following commands:

          Note: If the System Administrator demonstrates the use of an approved
      centralized account management method that locks an account after five
      unsuccessful logon attempts within a period of 120 minutes, this requirement is
      not applicable.

          Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
      RHEL version 8.2 or newer, this check is not applicable.

          $ sudo grep pam_faillock.so /etc/pam.d/password-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"dir\" option is not set to a non-default documented tally log
      directory on the \"preauth\" and \"authfail\" lines with the
      \"pam_faillock.so\" module, or is missing from these lines, this is a finding.

          $ sudo grep pam_faillock.so /etc/pam.d/system-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=3 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"dir\" option is not set to a non-default documented tally log
      directory on the \"preauth\" and \"authfail\" lines with the
      \"pam_faillock.so\" module, or is missing from these lines, this is a finding."

      desc 'fix', "Configure the operating system maintain the contents of the faillock
      directory after a reboot.

          Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
      \"/etc/pam.d/password-auth\" files to match the following lines:

          Note: Using the default faillock directory of /var/run/faillock will result
      in the contents being cleared in the event of a reboot.

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          The \"sssd\" service must be restarted for the changes to take effect. To
      restart the \"sssd\" service, run the following command:

          $ sudo systemctl restart sssd.service"
  end

  control 'SV-230340' do
      title, "RHEL 8 must prevent system messages from being presented when five
      unsuccessful logon attempts occur."

      desc 'check', "Check that the system prevents informative messages from being presented to
      the user pertaining to logon information with the following commands:

          Note: If the System Administrator demonstrates the use of an approved
      centralized account management method that locks an account after five
      unsuccessful logon attempts within a period of 120 minutes, this requirement is
      not applicable.

          Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
      RHEL version 8.2 or newer, this check is not applicable.

          $ sudo grep pam_faillock.so /etc/pam.d/password-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"silent\" option is missing from the \"preauth\" line with the
      \"pam_faillock.so\" module, this is a finding.

          $ sudo grep pam_faillock.so /etc/pam.d/system-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"silent\" option is missing from the \"preauth\" line with the
      \"pam_faillock.so\" module, this is a finding."
  end

  control 'SV-230341' do
      title, "RHEL 8 must prevent system messages from being presented when five
      unsuccessful logon attempts occur."
  end

  control 'SV-230344' do
      title, "RHEL 8 must include root when automatically locking an account until
      the locked account is released by an administrator when five unsuccessful
      logon attempts occur during a 120-minute time period."

      desc 'check', "Check that the system includes the root account when locking an account
      after five unsuccessful logon attempts within a period of 120 minutes with the
      following commands:

          If the system is RHEL version 8.2 or newer, this check is not applicable.

          Note: If the System Administrator demonstrates the use of an approved
      centralized account management method that locks an account after five
      unsuccessful logon attempts within a period of 120 minutes, this requirement is
      not applicable.

          $ sudo grep pam_faillock.so /etc/pam.d/password-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"even_deny_root\" option is missing from the \"preauth\" line with
      the \"pam_faillock.so\" module, this is a finding.

          $ sudo grep pam_faillock.so /etc/pam.d/system-auth

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=3 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          If the \"even_deny_root\" option is missing from the \"preauth\" line with
      the \"pam_faillock.so\" module, this is a finding."

      desc 'fix', "Configure the operating system to include root when locking an account
      after five unsuccessful logon attempts occur in 120 minutes.

          Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
      \"/etc/pam.d/password-auth\" files to match the following lines:

          auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
      deny=5 even_deny_root fail_interval=900 unlock_time=0
          auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
          account required pam_faillock.so

          The \"sssd\" service must be restarted for the changes to take effect. To
      restart the \"sssd\" service, run the following command:

          $ sudo systemctl restart sssd.service"
  end

  control 'SV-230345' do
      title, "RHEL 8 must include root when automatically locking an account until
      the locked account is released by an administrator when five unsuccessful
      logon attempts occur during a 120-minute time period."
  end

#  control 'SV-230483' do
#    title, "RHEL 8 must take action when allocated audit record storage volume
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

end