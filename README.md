# cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay
InSpec profile overlay to validate the secure configuration of Red Hat Enterprise Linux 8 against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Red Hat Enterprise Linux 8 STIG Version 1 Release 3 tailored for CMS ARS 5.0.

## Getting Started  
### InSpec (CINC-auditor) setup
For maximum flexibility/accessibility, we’re moving to “cinc-auditor”, the open-source packaged binary version of Chef InSpec, compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef’s always-open-source InSpec source code. For more information: https://cinc.sh/

It is intended and recommended that CINC-auditor and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

__For the best security of the runner, always install on the runner the _latest version_ of CINC-auditor.__ 

__The simplest way to install CINC-auditor is to use this command for a UNIX/Linux/MacOS runner platform:__
```
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```

__or this command for Windows runner platform (Powershell):__
```
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```
To confirm successful install of cinc-auditor:
```
cinc-auditor -v
```
> sample output:  _4.24.32_

Latest versions and other installation options are available at https://cinc.sh/start/auditor/.

## Specify your BASELINE system categization as an environment variable:

```
# BASELINE (choices: Low, Moderate, High)

on linux:
BASELINE=High

on Powershell:
$env:BASELINE="High"
```

## Tailoring to Your Environment

The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# Used by InSpec check SV-230309
# InSpec Tests that are known to consistently have long run times can be disabled with this attribute
# Description: Controls that are known to consistently have long run times can be disabled with this attribute
# Type: Boolean
# (default value): false
disable_slow_controls: 

# Used by InSpec check SV-230548
# Description: Flag to designate if the target is a container host
# Type: Boolean
# (default value): false
container_host:

# Used by InSpec check SV-230234
# Description: Main grub boot config file
# Type: String
# (default value): "/boot/efi/EFI/redhat/grub.cfg"
grub_uefi_main_cfg:

# Used by InSpec check SV-230234
# Description: Grub boot config files
# Type: Array
# (default value): ["/boot/efi/EFI/redhat/user.cfg"]
grub_uefi_user_boot_files: []

# Used by InSpec check SV-230317, SV-230321, SV-230322, SV-230325, SV-230328, SV-230309, SV-230320
# Description: Users exempt from home directory-based controls in array format
# Type: Array
# (default value): ["vagrant"]
exempt_home_users: []

# Used by InSpec check SV-230317, SV-230321, SV-230322, SV-230325, SV-230328, SV-230309, SV-230320
# Description: These shells do not allow a user to login
# Type: Array
# (default value):
#      - "/sbin/nologin"
#      - "/sbin/halt"
#      - "/sbin/shutdown"
#      - "/bin/false"
#      - "/bin/sync"
#      - "/bin/true"
non_interactive_shells: []

# Used by InSpec check SV-230379
# Description: System accounts that support approved system activities.
# Type: Array
# (default value):
#      - "root"
#      - "bin"
#      - "daemon"
#      - "adm"
#      - "lp"
#      - "sync"
#      - "shutdown"
#      - "halt"
#      - "mail"
#      - "operator"
#      - "nobody"
#      - "systemd-bus-proxy"
#      - "dbus"
#      - "polkitd"
#      - "postfix"
#      - "sssd"
#      - "chrony"
#      - "systemd-network"
#      - "sshd"
#      - "ntp"
known_system_accounts: []

# Description: Accounts of known managed users
# Type: Array
# (default value): ["vagrant"]
user_accounts: []

# Used by InSpec check SV-230379
# Description: The path to the logging package
# Type: String
# (default value): "/etc/rsyslog.conf"
log_pkg_path:

# Used by InSpec check SV-230235
# Description: Main grub boot config file
# Type: String
# (default value): "/boot/grub2/grub.cfg"
grub_main_cfg: 

# Description: Grub boot config files
# Type: Array
# (default value):["/boot/grub2/user.cfg"]
grub_user_boot_files: []

# Used by InSpec check SV-230537
# Description: Set to 'true' if IPv4 is enabled on the system.
# Type: Boolean
# (default value): true
ipv4_enabled:

# Used by InSpec check SV-230537
# Description: Set to 'true' if IPv6 is enabled on the system.
# Type: Boolean
# (default value): true
ipv6_enabled:

# Used by InSpec check SV-230493
# Description: Device or system does not have a camera installed.
# Type: Boolean
# (default value): true
camera_installed:

# Used by InSpec check SV-230503
# Description: 'Device or operating system has a Bluetooth adapter installed'
# Type: Boolean
# (default value): true
bluetooth_installed:

# Used by InSpec check SV-230242
# Description: System accounts that support approved system activities.
# Type: Array
# (default value): 
#      - 'root'
#      - 'bin'
#      - 'daemon'
#      - 'adm'
#      - 'lp'
#      - 'sync'
#      - 'shutdown'
#      - 'halt'
#      - 'mail'
#      - 'operator'
#      - 'nobody'
#      - 'systemd-bus-proxy'
#      - 'dbus'
#      - 'polkitd'
#      - 'postfix'
#      - 'sssd'
#      - 'chrony'
#      - 'systemd-network'
#      - 'sshd'
#      - 'ntp'
known_system_accounts: []

# Description: Smart card status (enabled or disabled)
# Type: String
# (default value): 'enabled'
smart_card_status: 

# Used by InSpec check SV-230263
# Description: Name of integrity checking tool
# Type: String
# (default value): 'aide'
file_integrity_tool: 

# Used by InSpec check SV-230484
# Description: Timeserver used in /etc/chrony.conf
# Type: String
# (default value): 0.us.pool.ntp.mil
authoritative_timeserver: 

# Used by InSpec check SV-230537
# Description: File systems listed in /etc/fstab which are not removable media devices
# Type: Array
# (default value): ["/", "/tmp", "none", "/home"]
non_removable_media_fs: []

# Used by InSpec check SV-230230
# Description: List of full paths to private key files on the system
# Type: Array
# (default value): []
private_key_files: []

# Used by InSpec check SV-230229
# Description: Path to an accepted trust anchor certificate file (DoD)
# Type: String
# (default value): "/etc/sssd/pki/sssd_auth_ca_db.pem"
root_ca_file: 

# Description: Temporary user accounts
# Type: Array
# (default value): []
temporary_accounts: []

# Description: Documented tally log directory
# Type: String
# (default value): '/var/log/faillock'
log_directory: 

```

## Running This Overlay Directly from Github

Against a remote target using ssh with escalated privileges (i.e., cinc-auditor installed on a separate runner host)
```bash
cinc-auditor exec https://github.com/CMSgov/cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay/archive/main.tar.gz -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --sudo --sudo-password=<SUDO_PASSWORD_IF_REQUIRED> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```

Against a remote target using a pem key with escalated privileges (i.e., cinc-auditor installed on a separate runner host)
```bash
cinc-auditor exec https://github.com/CMSgov/cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay/archive/main.tar.gz -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json>  
```

Against a local Red Hat host with escalated privileges (i.e., cinc-auditor installed on the target)
```bash
sudo cinc-auditor exec https://github.com/CMSgov/cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay/archive/main.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```
### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy
If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.) 

```
mkdir profiles
cd profiles
git clone https://github.com/CMSgov/cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay.git
cinc-auditor archive cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay
sudo cinc-auditor exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay
git pull
cd ..
cinc-auditor archive cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay --overwrite
sudo cinc-auditor exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.cms.gov/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall2)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Eugene Aronne
* Danny Haynes
* Mohamed El-Sharkawi

## Special Thanks
* The SIMP Project Team
* Aaron Lippold
* Sam Cornwell

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/CMSgov/cms-ars-5.0-red-hat-enterprise-linux-8-stig-overlay/issues/new).

### NOTICE

© 2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
