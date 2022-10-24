<!--
 * @Author: jentle
 * @Descriptio
 * @Date: 2022-10-18 15:50:17
 * @LastEditors: jentle
 * @LastEditTime: 2022-10-24 15:34:16
-->
# :star: 基础方案和原理
> :point_right: 内含 demo，编译环境：gcc (x86_64-posix-seh-rev0, Built by MinGW-W64 project) 8.1.0

## 1. :grin: IsDebuggerPresent
代码示例：
```
#include<stdio.h>
#include<windows.h>
#include<iostream>
using namespace std;

int main()
{
    if (IsDebuggerPresent())
    {
        cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    return 0;
} 
```

通过调试器，查看 `IsDebuggerPresent`源码可以看到：
```
0:000> u kernelBase!IsDebuggerPresent L3
KERNELBASE!IsDebuggerPresent:
00007ffb`ebf208d0 65488b042560000000 mov   rax,qword ptr gs:[60h]
00007ffb`ebf208d9 0fb64002        movzx   eax,byte ptr [rax+2]
00007ffb`ebf208dd c3              ret
```
32为：
```
0:000< u kernelbase!IsDebuggerPresent L3
KERNELBASE!IsDebuggerPresent:
751ca8d0 64a130000000    mov     eax,dword ptr fs:[00000030h]
751ca8d6 0fb64002        movzx   eax,byte ptr [eax+2]
751ca8da c3              ret 
```
详细 `PEB TEB`结构可以参考[附件](#附件)内容。

### 原理
`+0x060 ProcessEnvironmentBlock : Ptr64 _PEB` gs 指向程序的`_PEB`结构，其中 `_PEB` 偏移 0x2 位置是： `+0x002 BeingDebugged    : UChar`

所以该函数原理就是检查 `PEB` 下的 `BeingDebugged` 标志位。被调试是1 ， 否则0。

### PEB
你可以在代码中通过下面获取进程控制块地址：
```
PVOID GetPEB()
{
#ifdef _WIN64
    return (PVOID)__readgsqword(0x0C * sizeof(PVOID)); # PVOID 大小由编译器系统环境决定 4 or 8 bytes
#else
    return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}
```
如果程序是32位的，但是运行在64位系统上，遇到 WOW64 “天堂门”技术，可以通过下面代码，获取到单独创建的PEB结构：
你可以参考[Get 32bit PEB of another process from a x64 process](https://stackoverflow.com/questions/34736009/get-32bit-peb-of-another-process-from-a-x64-process)
同样的需求： 64位进程需要获取运行在WOW64中32位程序的PEB环境。

```
//  WOW64 
PVOID GetPEB64()
{
    PVOID pPeb = 0;
#ifndef _WIN64
    if (IsWin8OrHigher()) # S
    {
        BOOL isWow64 = FALSE;
        typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
        pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
            GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");
        if (fnIsWow64Process(GetCurrentProcess(), &isWow64))
        {
            if (isWow64)
            {
                pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
                pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
            }
        }
    }
#endif
    return pPeb;
} 
```
### BYPASS
直接给标志位置0：
```
mov eax, dword ptr fs:[0x30]  
mov byte ptr ds:[eax+2]

// x64
DWORD64 dwpeb = __readgsqword(0x60);
*((PBYTE)(dwpeb + 2)) = 0;
```

### 注意检查 TLS 回调
TLS在程序运行前以及运行了，记得检查是否由TLS回调函数，隐藏了反调试如：
```
#pragma section(".CRT$XLY", long, read)
__declspec(thread) int var = 0xDEADBEEF;
VOID NTAnopPI TlsCallback(PVOID DllHandle, DWORD Reason, VOID Reserved)
{
    var = 0xB15BADB0;
    if (IsDebuggerPresent())
    {
        MessageBoxA(NULL, "Stop debugging program!", "Error", MB_OK | MB_ICONERROR);
        TerminateProcess(GetCurrentProcess(), 0xBABEFACE);
    }
}
__declspec(allocate(".CRT$XLY"))PIMAGE_TLS_CALLBACK g_tlsCallback = TlsCallback;
       
```

## 2.:grin: NtGlobalFlag 
在 Windows NT 中，有一组标志存储在全局变量 NtGlobalFlag 中，这在整个系统中是通用的。在启动时，NtGlobalFlag 全局系统变量将使用系统注册表项中的值进行初始化：
`[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\GlobalFlag]`

要检查进程是否已使用调试器启动，请检查 PEB 结构中 NtGlobal 标志字段的值。此字段分别位于 x32 和 x64 系统的PEB 0x068和0x0bc偏移量。
```
0:000> dt _PEB NtGlobalFlag @$peb 
ntdll!_PEB
   +0x068 NtGlobalFlag : 0x70 

// x64
0:000> dt _PEB NtGlobalFlag @$peb
ntdll!_PEB
   +0x0bc NtGlobalFlag : 0x70 
```

### NtGlobalFlag 和 IMAGE_LOAD_CONFIG_DIRECTORY
可执行文件可以包含`IMAGE_LOAD_CONFIG_DIRECTORY`结构，该结构包含系统加载程序的其他配置参数。默认情况下，此结构不会内置于可执行文件中，但可以使用修补程序添加它。此结构具有`GlobalFlagsClear` ，该字段指示应重置 PEB 结构的 `NtGlobal` 标志字段的哪些标志。如果可执行文件最初是在没有上述结构的情况下创建的，或者 GlobalFlagsClear = 0，则在磁盘或内存中，该字段将具有非零值，表示存在隐藏的调试器。下面的代码示例检查正在运行的进程内存和磁盘上的全局标记清除字段，从而说明一种流行的反调试技术：
<details>
<summary>代码片段</summary>

```
PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pImageBase)
{
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    return (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);
}
PIMAGE_SECTION_HEADER FindRDataSection(PBYTE pImageBase)
{
    static const std::string rdata = ".rdata";
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
    int n = 0;
    for (; n < pImageNtHeaders->FileHeader.NumberOfSections; ++n)
    {
        if (rdata == (char*)pImageSectionHeader[n].Name)
        {
            break;
        }
    }
    return &pImageSectionHeader[n];
}
void CheckGlobalFlagsClearInProcess()
{
    PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pImageBase
        + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (pImageLoadConfigDirectory->GlobalFlagsClear != 0) #  内存中检查IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
}
void CheckGlobalFlagsClearInFile()
{
    HANDLE hExecutable = INVALID_HANDLE_VALUE;
    HANDLE hExecutableMapping = NULL;
    PBYTE pMappedImageBase = NULL;
    __try
    {
        PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
        PIMAGE_SECTION_HEADER pImageSectionHeader = FindRDataSection(pImageBase);
        TCHAR pszExecutablePath[MAX_PATH];
        DWORD dwPathLength = GetModuleFileName(NULL, pszExecutablePath, MAX_PATH);
        if (0 == dwPathLength) __leave;
        hExecutable = CreateFile(pszExecutablePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (INVALID_HANDLE_VALUE == hExecutable) __leave;
        hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
        if (NULL == hExecutableMapping) __leave;
        pMappedImageBase = (PBYTE)MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0,
            pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData);
        if (NULL == pMappedImageBase) __leave;
        PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pMappedImageBase);
        PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pMappedImageBase 
            + (pImageSectionHeader->PointerToRawData
                + (pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress - pImageSectionHeader->VirtualAddress)));
        if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
        {
            std::cout << "Stop debugging program!" << std::endl;
            exit(-1);
        }
    }
    __finally
    {
        if (NULL != pMappedImageBase)
            UnmapViewOfFile(pMappedImageBase);
        if (NULL != hExecutableMapping)
            CloseHandle(hExecutableMapping);
        if (INVALID_HANDLE_VALUE != hExecutable)
            CloseHandle(hExecutable);
    } 
} 
```

</details>

## 3. :smiley: 堆标志和 ForceFlags

在PEB中包含两个特殊标志位结构：
```
0:000> dt _PEB ProcessHeap @$peb
ntdll!_PEB
   +0x018 ProcessHeap : 0x00440000 Void
0:000> dt _HEAP Flags ForceFlags 00440000 
ntdll!_HEAP
   +0x040 Flags      : 0x40000062
   +0x044 ForceFlags : 0x40000060
```

x64:
```
0:000> dt _PEB ProcessHeap @$peb
ntdll!_PEB
   +0x030 ProcessHeap : 0x0000009d`94b60000 Void
0:000> dt _HEAP Flags ForceFlags 0000009d`94b60000
ntdll!_HEAP
   +0x070 Flags      : 0x40000062
   +0x074 ForceFlags : 0x40000060 
```

判断条件： 
- 如果 堆标志字段未设置HEAP_GROWABLE（0x00000002）标志，则正在调试进程。
- 如果ForceFlags值不为 0，则正在调试进程。

但在实际运行中根据操作系统不同可能会有一些偏差，下面是一个demo:
```
int GetHeapFlagsOffset(bool x64)
{
    return x64 ?
        IsVistaOrHigher() ? 0x70 : 0x14: //x64 offsets
        IsVistaOrHigher() ? 0x40 : 0x0C; //x86 offsets
}
int GetHeapForceFlagsOffset(bool x64)
{
    return x64 ?
        IsVistaOrHigher() ? 0x74 : 0x18: //x64 offsets
        IsVistaOrHigher() ? 0x44 : 0x10; //x86 offsets
}
void CheckHeap()
{
    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    PVOID heap = 0;
    DWORD offsetProcessHeap = 0;
    PDWORD heapFlagsPtr = 0, heapForceFlagsPtr = 0;
    BOOL x64 = FALSE;
#ifdef _WIN64
    x64 = TRUE;
    offsetProcessHeap = 0x30;
#else
    offsetProcessHeap = 0x18;
#endif
    heap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb + offsetProcessHeap);
    heapFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapFlagsOffset(x64));
    heapForceFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapForceFlagsOffset(x64));
    if (*heapFlagsPtr & ~HEAP_GROWABLE || *heapForceFlagsPtr != 0)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    if (pPeb64)
    {
        heap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
        heapFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapFlagsOffset(true));
        heapForceFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapForceFlagsOffset(true));
        if (*heapFlagsPtr & ~HEAP_GROWABLE || *heapForceFlagsPtr != 0)
        {
            std::cout << "Stop debugging program!" << std::endl;
            exit(-1);
        }
    }
}
  
```

## 4. :smiley: 检查 Trap Flag
陷阱标志（TF）位于EFLAGS寄存器内。如果 TF 设置为 1，CPU 将在每次指令执行后生成 INT 01h 或“单步”异常。以下反调试示例基于 TF 设置和异常调用检查：
```
BOOL isDebugged = TRUE;
__try
{
    __asm
    {
        pushfd
        or dword ptr[esp], 0x100 // 设置Trap Flag 
        popfd                    // 回复eflags
        nop
    }
}
__except (EXCEPTION_EXECUTE_HANDLER)
{
    // 如果有异常，则调试器不存在
    isDebugged = FALSE;
}
if (isDebugged)
{
    std::cout << "Stop debugging program!" << std::endl;
    exit(-1);
}
```

### BYPASS
遇到类似`pushfd`的时候小心点，不要单步，下断点也要在它后面。

## 5. :grin: API CheckRemoteDebuggerPresent 和 NtQueryInformationProcess
通过另外一个并行的程序检查目标程序是否在被调试：
```
int main(int argc, char *argv[])
{
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent ))
    {
        if (isDebuggerPresent )
        {
            std::cout << "Stop debugging program!" << std::endl;
            exit(-1);
        }
    }
    return 0;
}
```
CheckRemoteDebuggerPresent内部调用了 NtQueryInformationProcess ：
```
0:000> uf kernelbase!CheckRemotedebuggerPresent
KERNELBASE!CheckRemoteDebuggerPresent:
...
75207a24 6a00            push    0
75207a26 6a04            push    4
75207a28 8d45fc          lea     eax,[ebp-4]
75207a2b 50              push    eax
75207a2c 6a07            push    7
75207a2e ff7508          push    dword ptr [ebp+8]
75207a31 ff151c602775    call    dword ptr [KERNELBASE!_imp__NtQueryInformationProcess (7527601c)]
75207a37 85c0            test    eax,eax
75207a39 0f88607e0100    js      KERNELBASE!CheckRemoteDebuggerPresent+0x2b (7521f89f)
```
CheckRemoteDebuggerPresent 依据 `DebugPort ` 的值，也就是 `ProcessInformationClass` 的第二个值是 7. 根据原理的函数原型demo:
```
typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
    _In_      HANDLE           ProcessHandle,
    _In_      UINT             ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );
const UINT ProcessDebugPort = 7;
int main(int argc, char *argv[])
{
    pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
    NTSTATUS status;
    DWORD isDebuggerPresent = 0;
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
     
    if (NULL != hNtDll)
    {
        NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        if (NULL != NtQueryInformationProcess)
        {
            status = NtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &isDebuggerPresent,
                sizeof(DWORD),
                NULL);
            if (status == 0x00000000 && isDebuggerPresent != 0)
            {
                std::cout << "Stop debugging program!" << std::endl;
                exit(-1);
            }
        }
    }
    return 0;
} 
```
### BYPASS
通过hook api NtQueryInformationProcess 修改返回值，如用 [mhook](https://github.com/martona/mhook):

<details>

```
#include <Windows.h>
#include "mhook.h"
typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
    _In_      HANDLE           ProcessHandle,
    _In_      UINT             ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );
const UINT ProcessDebugPort = 7;
pfnNtQueryInformationProcess g_origNtQueryInformationProcess = NULL;
NTSTATUS NTAPI HookNtQueryInformationProcess(
    _In_      HANDLE           ProcessHandle,
    _In_      UINT             ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    )
{
    NTSTATUS status = g_origNtQueryInformationProcess(
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength);
    if (status == 0x00000000 && ProcessInformationClass == ProcessDebugPort)
    {
        *((PDWORD_PTR)ProcessInformation) = 0;
    }
    return status;
}
DWORD SetupHook(PVOID pvContext)
{
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (NULL != hNtDll)
    {
        g_origNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        if (NULL != g_origNtQueryInformationProcess)
        {
            Mhook_SetHook((PVOID*)&g_origNtQueryInformationProcess, HookNtQueryInformationProcess);
        }
    }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstDLL);
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SetupHook, NULL, NULL, NULL);
        Sleep(20);
    case DLL_PROCESS_DETACH:
        if (NULL != g_origNtQueryInformationProcess)
        {
            Mhook_Unhook((PVOID*)&g_origNtQueryInformationProcess);
        }
        break;
    }
    return TRUE;
} 
```

</details>




`NtQueryInformationProcess` 中其他可以用作判断调试标志位的：
- ProcessDebugPort 0x07 – discussed above
- ProcessDebugObjectHandle 0x1E
- ProcessDebugFlags 0x1F
- ProcessBasicInformation 0x00

## 6. :grin: ProcessDebugObjectHandle
从 Windows XP 开始，为调试的进程创建一个“调试对象”。下面是在当前进程中检查“调试对象”的示例：
```
status = NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &hProcessDebugObject,
            sizeof(HANDLE),
            NULL);
if (0x00000000 == status && NULL != hProcessDebugObject)
{
    std::cout << "Stop debugging program!" << std::endl;
    exit(-1);
}
```
## 7. :smile: ProcessDebugFlags
`EPROCESS` 内核结构中的 `NoDebugInherit`, 对应 `NtQueryInformationProcess` 的返回值如下
```
status = NtQueryInformationProcess(
    GetCurrentProcess(),
    ProcessDebugObjectHandle,
    &debugFlags,
    sizeof(ULONG),
    NULL);
if (0x00000000 == status && NULL != debugFlags)
{
    std::cout << "Stop debugging program!" << std::endl;
    exit(-1);
} 
```
## 8. ProcessBasicInformation
调用带有 `ProcessBasicInformation` 标志的 `NtQueryInformationProcess `函数时，返回 `PROCESS_BASIC_INFORMATION` 结构如下：
```
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION; 
```
通过 `InheritedFromUniqueProcessId ` 获取父进程的名字，并和常见的调试器进行比较来anti：
<details>
<summary>demo</summary>

```
std::wstring GetProcessNameById(DWORD pid)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return 0;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    std::wstring processName = L"";
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return processName;
    }
    do
    {
        if (pe32.th32ProcessID == pid)
        {
            processName = pe32.szExeFile;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
     
    CloseHandle(hProcessSnap);
    return processName;
}
status = NtQueryInformationProcess(
    GetCurrentProcess(),
    ProcessBasicInformation,
    &processBasicInformation,
    sizeof(PROCESS_BASIC_INFORMATION),
    NULL);
std::wstring parentProcessName = GetProcessNameById((DWORD)processBasicInformation.InheritedFromUniqueProcessId);
if (L"devenv.exe" == parentProcessName)
{
    std::cout << "Stop debugging program!" << std::endl;
    exit(-1);
}
```
</details>


所以对抗的方式可以总结为三点：
  -  置 ProcessDebugObjectHandle 为 0
  - 置 ProcessDebugFlags 为 1
  - InheritedFromUniqueProcessId 设置成其他值

## 9. :sunglasses: 软件断点
检查 INT 3 (0xCC) 断点,下面的demo检查两个函数之间的长度：（ /INCREMENTAL:NO）
```
DWORD CalcFuncCrc(PUCHAR funcBegin, PUCHAR funcEnd)
{
    DWORD crc = 0;
    for (; funcBegin < funcEnd; ++funcBegin)
    {
        crc += *funcBegin;
    }
    return crc;
}
#pragma auto_inline(off)
VOID DebuggeeFunction()
{
    int calc = 0;
    calc += 2;
    calc <<= 8;
    calc -= 3;
}
VOID DebuggeeFunctionEnd()
{
};
#pragma auto_inline(on)
DWORD g_origCrc = 0x2bd0;
int main()
{
    DWORD crc = CalcFuncCrc((PUCHAR)DebuggeeFunction, (PUCHAR)DebuggeeFunctionEnd);
    if (g_origCrc != crc)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    return 0;
} 
```

BYPASS的方案就是发现类似的函数或者计算的时候，NOP掉或者其他。重在看见该方案。

## 10. 硬件断点
x86机构下的特殊硬件寄存器：
  - DR0-DR3 – 断点寄存器
  - DR4 & DR5 – 保留
  - DR6 – 调试状态
  - DR7 – 调试控制。


通用方案：
```
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
if (GetThreadContext(GetCurrentThread(), &ctx))
{
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
}  
```
可以重置：
```
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
SetThreadContext(GetCurrentThread(), &ctx); 
```
### BYPSS
看一下`GetThreadContext `函数调用内部,调用了 `_imp__NtGetContextThread`:
```
KERNELBASE!GetThreadContext:
7538d580 8bff            mov     edi,edi
7538d582 55              push    ebp
7538d583 8bec            mov     ebp,esp
7538d585 ff750c          push    dword ptr [ebp+0Ch]
7538d588 ff7508          push    dword ptr [ebp+8]
7538d58b ff1504683975    call    dword ptr [KERNELBASE!_imp__NtGetContextThread (75396804)] 
```
bypass的思路就是修改 `CONTEXT` 结构中 `ContextFlags `中的 `CONTEXT_DEBUG_REGISTERS`标志位。并在原始调用结束后恢复线程环境。
```
typedef NTSTATUS(NTAPI *pfnNtGetContextThread)(
    _In_  HANDLE             ThreadHandle,
    _Out_ PCONTEXT           pContext
    );
typedef NTSTATUS(NTAPI *pfnNtSetContextThread)(
    _In_ HANDLE              ThreadHandle,
    _In_ PCONTEXT            pContext
    );
pfnNtGetContextThread g_origNtGetContextThread = NULL;
pfnNtSetContextThread g_origNtSetContextThread = NULL;
NTSTATUS NTAPI HookNtGetContextThread(
    _In_  HANDLE              ThreadHandle,
    _Out_ PCONTEXT            pContext)
{
    DWORD backupContextFlags = pContext->ContextFlags;
    pContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    NTSTATUS status = g_origNtGetContextThread(ThreadHandle, pContext);
    pContext->ContextFlags = backupContextFlags;
    return status;
}
NTSTATUS NTAPI HookNtSetContextThread(
    _In_ HANDLE              ThreadHandle,
    _In_ PCONTEXT            pContext)
{
    DWORD backupContextFlags = pContext->ContextFlags;
    pContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    NTSTATUS status = g_origNtSetContextThread(ThreadHandle, pContext);   
    pContext->ContextFlags = backupContextFlags;
    return status;
}
void HookThreadContext()
{
  HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
  g_origNtGetContextThread = (pfnNtGetContextThread)GetProcAddress(hNtDll, "NtGetContextThread");
  g_origNtSetContextThread = (pfnNtSetContextThread)GetProcAddress(hNtDll, "NtSetContextThread");
  Mhook_SetHook((PVOID*)&g_origNtGetContextThread, HookNtGetContextThread);
  Mhook_SetHook((PVOID*)&g_origNtSetContextThread, HookNtSetContextThread);
} 
```

## 11. :shit: SEH (Structured Exception Handling)
SEH链地址在fs/gs寄存器的0偏移位置，指向`_EXCEPTION_REGISTRATION_RECORD`结构：
```
0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : Ptr32 _EXCEPTION_DISPOSITION 
```
当处理异常时，优先使用程序的异常处理程序，并返回`_EXCEPTION_DISPOSITION`结果：
```
typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution,
    ExceptionContinueSearch,
    ExceptionNestedException,
    ExceptionCollidedUnwind
} EXCEPTION_DISPOSITION;
```
而如果返回的是`ExceptionContinueSearch`，就代表当前SEH无法处理，继续查找，可以通过 `!exchain`查看：
```
0:000> !exchain
00a5f3bc: AntiDebug!_except_handler4+0 (008b7530)
  CRT scope  0, filter: AntiDebug!SehInternals+67 (00883d67)
                func:   AntiDebug!SehInternals+6d (00883d6d)
00a5f814: AntiDebug!__scrt_stub_for_is_c_termination_complete+164b (008bc16b)
00a5f87c: AntiDebug!_except_handler4+0 (008b7530)
  CRT scope  0, filter: AntiDebug!__scrt_common_main_seh+1b0 (008b7c60)
                func:   AntiDebug!__scrt_common_main_seh+1cb (008b7c7b)
00a5f8e8: ntdll!_except_handler4+0 (775674a0)
  CRT scope  0, filter: ntdll!__RtlUserThreadStart+54386 (7757f076)
                func:   ntdll!__RtlUserThreadStart+543cd (7757f0bd)
00a5f900: ntdll!FinalExceptionHandlerPad4+0 (77510213)
```
注册表中存着系统SEH默认项：
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\AeDebug`

调试器中 INT3 后会接管程序控制，所以可以通过SEH检查反调试：
```
BOOL g_isDebuggerPresent = TRUE;
EXCEPTION_DISPOSITION ExceptionRoutine(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID             EstablisherFrame,
    PCONTEXT          ContextRecord,
    PVOID             DispatcherContext)
{
    g_isDebuggerPresent = FALSE;
    ContextRecord->Eip += 1;
    return ExceptionContinueExecution;
}
int main()
{
    __asm
    {
        // 设置 SEH handler
        push ExceptionRoutine
        push dword ptr fs:[0]
        mov  dword ptr fs:[0], esp
        // 生成中断
        int  3h
        // 返回原始 SEH handler
        mov  eax, [esp]
        mov  dword ptr fs:[0], eax
        add  esp, 8
    }
    if (g_isDebuggerPresent)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    return 0
} 
```
上面这段程序在SEH链中插入一个新的异常处理，如果INT 3 之后进入的是该SEH，那么`g_isDebuggerPresent`接受到被置为FALSE，并继续下一个SEH处理，反之如果调试器接受到的话就是 TRUE 带入后面判断。

### BYPSS
数据调用SEH会调用`ExecuteHandler2`，该函数是所有SEH的起点，断点到这，然后逐个跟踪~~~~ :tada:
```
0:000> u ntdll!ExecuteHandler2+24 L3
ntdll!ExecuteHandler2+0x24:
775100af ffd1            call    ecx
775100b1 648b2500000000  mov     esp,dword ptr fs:[0]
775100b8 648f0500000000  pop     dword ptr fs:[0]
```

## 12. VEH (Vectored Exception Handler)
VEH 链路保存在`ntdll!LdrpVectorHandlerListIt ` 中，它和SEH不互相冲突，区别在于VEH的创建，删除和签名：
```
PVOID WINAPI AddVectoredExceptionHandler(
    ULONG                       FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
);
ULONG WINAPI RemoveVectoredExceptionHandler(
    PVOID Handler
);
LONG CALLBACK VectoredHandler(
    PEXCEPTION_POINTERS ExceptionInfo
);
The _EXCEPTION_POINTERS structure looks like this:  
typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS; 
```
收到系统控制之后，通过`ContextRecord ` 参数传递保存的上下文结构，demo:
```
LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    ctx->Eip += 2;
    return EXCEPTION_CONTINUE_EXECUTION;
}
int main()
{
    AddVectoredExceptionHandler(0, ExceptionHandler);
    __asm int 1h;
    return 0;
}
```
我们设置了一个 VEH 处理程序并生成了中断（int 1h非必须）。生成中断时，将显示异常，并将控制权转移到 VEH 处理程序。此时检查硬件断点。如果没有硬件断点，则 EIP 寄存器值增加 2，以便在 int 1h 指令后继续执行。

### BYPSS
上面的程序，我们可以通过：
```
0:000> kn
 # ChildEBP RetAddr  
00 001cf21c 774d6822 AntiDebug!ExceptionHandler 
01 001cf26c 7753d151 ntdll!RtlpCallVectoredHandlers+0xba
02 001cf304 775107ff ntdll!RtlDispatchException+0x72
03 001cf304 00bf4a69 ntdll!KiUserExceptionDispatcher+0xf
04 001cfc1c 00c2680e AntiDebug!main+0x59 
05 001cfc30 00c2665a AntiDebug!invoke_main+0x1e 
06 001cfc88 00c264ed AntiDebug!__scrt_common_main_seh+0x15a 
07 001cfc90 00c26828 AntiDebug!__scrt_common_main+0xd 
08 001cfc98 753e7c04 AntiDebug!mainCRTStartup+0x8 
09 001cfcac 7752ad1f KERNEL32!BaseThreadInitThunk+0x24
0a 001cfcf4 7752acea ntdll!__RtlUserThreadStart+0x2f
0b 001cfd04 00000000 ntdll!_RtlUserThreadStart+0x1b 
```
可以看到函数在调用`main+0x59 `之前，调用了 `ntdll!KiUserExceptionDispatcher`,而`main+0x59 `位置就是：
```
0:000> u main+59 L1
AntiDebug!main+0x59
00bf4a69 cd02            int     1 
```
所以我们可以hook `ntdll!KiUserExceptionDispatcher`,
```
typedef  VOID (NTAPI *pfnKiUserExceptionDispatcher)(
    PEXCEPTION_RECORD pExcptRec,
    PCONTEXT ContextFrame
    );
pfnKiUserExceptionDispatcher g_origKiUserExceptionDispatcher = NULL;
VOID NTAPI HandleKiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame)
{
    if (ContextFrame && (CONTEXT_DEBUG_REGISTERS & ContextFrame->ContextFlags))
    {
        ContextFrame->Dr0 = 0;
        ContextFrame->Dr1 = 0;
        ContextFrame->Dr2 = 0;
        ContextFrame->Dr3 = 0;
        ContextFrame->Dr6 = 0;
        ContextFrame->Dr7 = 0;
        ContextFrame->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    }
}
__declspec(naked) VOID NTAPI HookKiUserExceptionDispatcher() 
// Params: PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame
{
    __asm
    {
        mov eax, [esp + 4]
        mov ecx, [esp]
        push eax
        push ecx
        call HandleKiUserExceptionDispatcher
        jmp g_origKiUserExceptionDispatcher
    }
}
int main()
{
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    g_origKiUserExceptionDispatcher = (pfnKiUserExceptionDispatcher)GetProcAddress(hNtDll, "KiUserExceptionDispatcher");
    Mhook_SetHook((PVOID*)&g_origKiUserExceptionDispatcher, HookKiUserExceptionDispatcher);
    return 0;
}
```
上面的例子中，在调用`HookKiUserExceptionDispatcher` 重置 DRx寄存器，也就是在VEH前。

## 13.NtSetInformationThreadIt
> 隐藏线程

在Windows 2000中，出现了传输到`NtSetInformationThread`函数的线程信息——`ThreadHideFromDebugger`。这是Windows提供的第一个反调试技术之一，用于微软搜索如何防止逆向，它非常强大。如果为线程设置了此标志，则该线程将停止发送有关调试事件的通知。这些事件包括断点和程序完成通知。此标志的值存储在`_ETHREAD`结构的`HideFromDebugger`字段中：
```
> dt _ETHREAD HideFromDebugger 86bfada8
ntdll!_ETHREAD
   +0x248 HideFromDebugger : 0y1 
```
下面是一个设置`ThreadHideFromDebugger`例子：
```
typedef NTSTATUS (NTAPI *pfnNtSetInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG  ThreadInformationClass,
    _In_ PVOID  ThreadInformation,
    _In_ ULONG  ThreadInformationLength
    );
const ULONG ThreadHideFromDebugger = 0x11;
void HideFromDebugger()
{
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
        GetProcAddress(hNtDll, "NtSetInformationThread");
    NTSTATUS status = NtSetInformationThread(GetCurrentThread(), 
        ThreadHideFromDebugger, NULL, 0);
}
```
对抗的方法就是hook `NtSetInformationThread`:
```
pfnNtSetInformationThread g_origNtSetInformationThread = NULL;
NTSTATUS NTAPI HookNtSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG  ThreadInformationClass,
    _In_ PVOID  ThreadInformation,
    _In_ ULONG  ThreadInformationLength
    )
{
    if (ThreadInformationClass == ThreadHideFromDebugger && 
        ThreadInformation == 0 && ThreadInformationLength == 0)
    {
        return STATUS_SUCCESS;
    }
    return g_origNtSetInformationThread(ThreadHandle, 
        ThreadInformationClass, ThreadInformation, ThreadInformationLength
}
                                         
void SetHook()
{
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (NULL != hNtDll)
    {
        g_origNtSetInformationThread = (pfnNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");
        if (NULL != g_origNtSetInformationThread)
        {
            Mhook_SetHook((PVOID*)&g_origNtSetInformationThread, HookNtSetInformationThread);
        }
    }
}
```
返回 `STATUS_SUCCESS `,而不是调用 `NtSetInformationThread`

## 14.:last_quarter_moon:NtCreateThreadEx
Vista之后引入的结构`NtCreateThreadEx `，如下：
```
NTSTATUS NTAPI NtCreateThreadEx (
    _Out_    PHANDLE              ThreadHandle,
    _In_     ACCESS_MASK          DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES   ObjectAttributes,
    _In_     HANDLE               ProcessHandle,
    _In_     PVOID                StartRoutine,
    _In_opt_ PVOID                Argument,
    _In_     ULONG                CreateFlags,
    _In_opt_ ULONG_PTR            ZeroBits,
    _In_opt_ SIZE_T               StackSize,
    _In_opt_ SIZE_T               MaximumStackSize,
    _In_opt_ PVOID                AttributeList
);
```
其中 `CreateFlags` 结果如下：
```
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080
```
如果一个新线程获得thread_CREATE_FLAGS_HIDE_FROM_DEBUGGER标志，那么它将在创建时对调试器隐藏。这是由NtSetInformationThread函数设置的和ThreadHideFromDebugger一样。负责安全任务的代码可以在设置了thread_CREATE_FLAGS_HIDE_FROM_DEBUGGER标志的线程中执行。

对抗的方法就是 hook NtCreateThreadEx 并重置 `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER`

## 15.:jack_o_lantern: Handle tracing(句柄跟踪)
从Windows XP开始，Windows系统就有了内核对象句柄跟踪机制。当跟踪模式打开时，所有带有处理程序的操作都会保存到循环缓冲区中，此外，当尝试使用不存在的处理程序时，例如使用CloseHandle函数关闭它时，将生成EXCEPTION_INVALID_HANDLE异常。如果进程不是从调试器启动的，CloseHandle函数将返回FALSE。以下示例显示了基于CloseHandle的反调试保护：
```
EXCEPTION_DISPOSITION ExceptionRoutine(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID             EstablisherFrame,
    PCONTEXT          ContextRecord,
    PVOID             DispatcherContext)
{
    if (EXCEPTION_INVALID_HANDLE == ExceptionRecord->ExceptionCode)
    {
        std::cout << "Stop debugging program!" << std::endl;
        exit(-1);
    }
    return ExceptionContinueExecution;
}
int main()
{
    __asm
    {
        // 设置 SEH handler
        push ExceptionRoutine
        push dword ptr fs : [0]
        mov  dword ptr fs : [0], esp
    }
    CloseHandle((HANDLE)0xBAAD);
    __asm
    {
        // 返回原始 SEH handler
        mov  eax, [esp]
        mov  dword ptr fs : [0], eax
        add  esp, 8
    }
    return 0
} 
```

## :bath:总结：
这只是沧海一粟的方案，推荐阅读：
1. [内存反调试](https://sidechannel.tempestsi.com/ba-ad-f0-0d-using-memory-debug-code-as-an-anti-debugging-technique-116666184beb)
2. `NtQueryObject`
3. [计时器方案](https://www.apriorit.com/dev-blog/298-anti-debug-time-plugin)
4. `NtSetDebugFilterState`


# :shit: 附件
<details>
<summary>x64 _TEB 结构</summary>   

```
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x038 EnvironmentPointer : Ptr64 Void
   +0x040 ClientId         : _CLIENT_ID
   +0x050 ActiveRpcHandle  : Ptr64 Void
   +0x058 ThreadLocalStoragePointer : Ptr64 Void
   +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
   +0x068 LastErrorValue   : Uint4B
   +0x06c CountOfOwnedCriticalSections : Uint4B
   +0x070 CsrClientThread  : Ptr64 Void
   +0x078 Win32ThreadInfo  : Ptr64 Void
   +0x080 User32Reserved   : [26] Uint4B
   +0x0e8 UserReserved     : [5] Uint4B
   +0x100 WOW32Reserved    : Ptr64 Void
   +0x108 CurrentLocale    : Uint4B
   +0x10c FpSoftwareStatusRegister : Uint4B
   +0x110 ReservedForDebuggerInstrumentation : [16] Ptr64 Void
   +0x190 SystemReserved1  : [30] Ptr64 Void
   +0x280 PlaceholderCompatibilityMode : Char
   +0x281 PlaceholderHydrationAlwaysExplicit : UChar
   +0x282 PlaceholderReserved : [10] Char
   +0x28c ProxiedProcessId : Uint4B
   +0x290 _ActivationStack : _ACTIVATION_CONTEXT_STACK
   +0x2b8 WorkingOnBehalfTicket : [8] UChar
   +0x2c0 ExceptionCode    : Int4B
   +0x2c4 Padding0         : [4] UChar
   +0x2c8 ActivationContextStackPointer : Ptr64 _ACTIVATION_CONTEXT_STACK
   +0x2d0 InstrumentationCallbackSp : Uint8B
   +0x2d8 InstrumentationCallbackPreviousPc : Uint8B
   +0x2e0 InstrumentationCallbackPreviousSp : Uint8B
   +0x2e8 TxFsContext      : Uint4B
   +0x2ec InstrumentationCallbackDisabled : UChar
   +0x2ed UnalignedLoadStoreExceptions : UChar
   +0x2ee Padding1         : [2] UChar
   +0x2f0 GdiTebBatch      : _GDI_TEB_BATCH
   +0x7d8 RealClientId     : _CLIENT_ID
   +0x7e8 GdiCachedProcessHandle : Ptr64 Void
   +0x7f0 GdiClientPID     : Uint4B
   +0x7f4 GdiClientTID     : Uint4B
   +0x7f8 GdiThreadLocalInfo : Ptr64 Void
   +0x800 Win32ClientInfo  : [62] Uint8B
   +0x9f0 glDispatchTable  : [233] Ptr64 Void
   +0x1138 glReserved1      : [29] Uint8B
   +0x1220 glReserved2      : Ptr64 Void
   +0x1228 glSectionInfo    : Ptr64 Void
   +0x1230 glSection        : Ptr64 Void
   +0x1238 glTable          : Ptr64 Void
   +0x1240 glCurrentRC      : Ptr64 Void
   +0x1248 glContext        : Ptr64 Void
   +0x1250 LastStatusValue  : Uint4B
   +0x1254 Padding2         : [4] UChar
   +0x1258 StaticUnicodeString : _UNICODE_STRING
   +0x1268 StaticUnicodeBuffer : [261] Wchar
   +0x1472 Padding3         : [6] UChar
   +0x1478 DeallocationStack : Ptr64 Void
   +0x1480 TlsSlots         : [64] Ptr64 Void
   +0x1680 TlsLinks         : _LIST_ENTRY
   +0x1690 Vdm              : Ptr64 Void
   +0x1698 ReservedForNtRpc : Ptr64 Void
   +0x16a0 DbgSsReserved    : [2] Ptr64 Void
   +0x16b0 HardErrorMode    : Uint4B
   +0x16b4 Padding4         : [4] UChar
   +0x16b8 Instrumentation  : [11] Ptr64 Void
   +0x1710 ActivityId       : _GUID
   +0x1720 SubProcessTag    : Ptr64 Void
   +0x1728 PerflibData      : Ptr64 Void
   +0x1730 EtwTraceData     : Ptr64 Void
   +0x1738 WinSockData      : Ptr64 Void
   +0x1740 GdiBatchCount    : Uint4B
   +0x1744 CurrentIdealProcessor : _PROCESSOR_NUMBER
   +0x1744 IdealProcessorValue : Uint4B
   +0x1744 ReservedPad0     : UChar
   +0x1745 ReservedPad1     : UChar
   +0x1746 ReservedPad2     : UChar
   +0x1747 IdealProcessor   : UChar
   +0x1748 GuaranteedStackBytes : Uint4B
   +0x174c Padding5         : [4] UChar
   +0x1750 ReservedForPerf  : Ptr64 Void
   +0x1758 ReservedForOle   : Ptr64 Void
   +0x1760 WaitingOnLoaderLock : Uint4B
   +0x1764 Padding6         : [4] UChar
   +0x1768 SavedPriorityState : Ptr64 Void
   +0x1770 ReservedForCodeCoverage : Uint8B
   +0x1778 ThreadPoolData   : Ptr64 Void
   +0x1780 TlsExpansionSlots : Ptr64 Ptr64 Void
   +0x1788 DeallocationBStore : Ptr64 Void
   +0x1790 BStoreLimit      : Ptr64 Void
   +0x1798 MuiGeneration    : Uint4B
   +0x179c IsImpersonating  : Uint4B
   +0x17a0 NlsCache         : Ptr64 Void
   +0x17a8 pShimData        : Ptr64 Void
   +0x17b0 HeapData         : Uint4B
   +0x17b4 Padding7         : [4] UChar
   +0x17b8 CurrentTransactionHandle : Ptr64 Void
   +0x17c0 ActiveFrame      : Ptr64 _TEB_ACTIVE_FRAME
   +0x17c8 FlsData          : Ptr64 Void
   +0x17d0 PreferredLanguages : Ptr64 Void
   +0x17d8 UserPrefLanguages : Ptr64 Void
   +0x17e0 MergedPrefLanguages : Ptr64 Void
   +0x17e8 MuiImpersonation : Uint4B
   +0x17ec CrossTebFlags    : Uint2B
   +0x17ec SpareCrossTebBits : Pos 0, 16 Bits
   +0x17ee SameTebFlags     : Uint2B
   +0x17ee SafeThunkCall    : Pos 0, 1 Bit
   +0x17ee InDebugPrint     : Pos 1, 1 Bit
   +0x17ee HasFiberData     : Pos 2, 1 Bit
   +0x17ee SkipThreadAttach : Pos 3, 1 Bit
   +0x17ee WerInShipAssertCode : Pos 4, 1 Bit
   +0x17ee RanProcessInit   : Pos 5, 1 Bit
   +0x17ee ClonedThread     : Pos 6, 1 Bit
   +0x17ee SuppressDebugMsg : Pos 7, 1 Bit
   +0x17ee DisableUserStackWalk : Pos 8, 1 Bit
   +0x17ee RtlExceptionAttached : Pos 9, 1 Bit
   +0x17ee InitialThread    : Pos 10, 1 Bit
   +0x17ee SessionAware     : Pos 11, 1 Bit
   +0x17ee LoadOwner        : Pos 12, 1 Bit
   +0x17ee LoaderWorker     : Pos 13, 1 Bit
   +0x17ee SkipLoaderInit   : Pos 14, 1 Bit
   +0x17ee SpareSameTebBits : Pos 15, 1 Bit
   +0x17f0 TxnScopeEnterCallback : Ptr64 Void
   +0x17f8 TxnScopeExitCallback : Ptr64 Void
   +0x1800 TxnScopeContext  : Ptr64 Void
   +0x1808 LockCount        : Uint4B
   +0x180c WowTebOffset     : Int4B
   +0x1810 ResourceRetValue : Ptr64 Void
   +0x1818 ReservedForWdf   : Ptr64 Void
   +0x1820 ReservedForCrt   : Uint8B
   +0x1828 EffectiveContainerId : _GUID
```


</details>

<details>
<summary>x64 _PEB 结构</summary>     

```
ntdll!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
   +0x003 IsPackagedProcess : Pos 4, 1 Bit
   +0x003 IsAppContainer   : Pos 5, 1 Bit
   +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
   +0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
   +0x004 Padding0         : [4] UChar
   +0x008 Mutant           : Ptr64 Void
   +0x010 ImageBaseAddress : Ptr64 Void
   +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
   +0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
   +0x028 SubSystemData    : Ptr64 Void
   +0x030 ProcessHeap      : Ptr64 Void
   +0x038 FastPebLock      : Ptr64 _RTL_CRITICAL_SECTION
   +0x040 AtlThunkSListPtr : Ptr64 _SLIST_HEADER
   +0x048 IFEOKey          : Ptr64 Void
   +0x050 CrossProcessFlags : Uint4B
   +0x050 ProcessInJob     : Pos 0, 1 Bit
   +0x050 ProcessInitializing : Pos 1, 1 Bit
   +0x050 ProcessUsingVEH  : Pos 2, 1 Bit
   +0x050 ProcessUsingVCH  : Pos 3, 1 Bit
   +0x050 ProcessUsingFTH  : Pos 4, 1 Bit
   +0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
   +0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
   +0x050 ProcessImagesHotPatched : Pos 7, 1 Bit
   +0x050 ReservedBits0    : Pos 8, 24 Bits
   +0x054 Padding1         : [4] UChar
   +0x058 KernelCallbackTable : Ptr64 Void
   +0x058 UserSharedInfoPtr : Ptr64 Void
   +0x060 SystemReserved   : Uint4B
   +0x064 AtlThunkSListPtr32 : Uint4B
   +0x068 ApiSetMap        : Ptr64 Void
   +0x070 TlsExpansionCounter : Uint4B
   +0x074 Padding2         : [4] UChar
   +0x078 TlsBitmap        : Ptr64 Void
   +0x080 TlsBitmapBits    : [2] Uint4B
   +0x088 ReadOnlySharedMemoryBase : Ptr64 Void
   +0x090 SharedData       : Ptr64 Void
   +0x098 ReadOnlyStaticServerData : Ptr64 Ptr64 Void
   +0x0a0 AnsiCodePageData : Ptr64 Void
   +0x0a8 OemCodePageData  : Ptr64 Void
   +0x0b0 UnicodeCaseTableData : Ptr64 Void
   +0x0b8 NumberOfProcessors : Uint4B
   +0x0bc NtGlobalFlag     : Uint4B
   +0x0c0 CriticalSectionTimeout : _LARGE_INTEGER
   +0x0c8 HeapSegmentReserve : Uint8B
   +0x0d0 HeapSegmentCommit : Uint8B
   +0x0d8 HeapDeCommitTotalFreeThreshold : Uint8B
   +0x0e0 HeapDeCommitFreeBlockThreshold : Uint8B
   +0x0e8 NumberOfHeaps    : Uint4B
   +0x0ec MaximumNumberOfHeaps : Uint4B
   +0x0f0 ProcessHeaps     : Ptr64 Ptr64 Void
   +0x0f8 GdiSharedHandleTable : Ptr64 Void
   +0x100 ProcessStarterHelper : Ptr64 Void
   +0x108 GdiDCAttributeList : Uint4B
   +0x10c Padding3         : [4] UChar
   +0x110 LoaderLock       : Ptr64 _RTL_CRITICAL_SECTION
   +0x118 OSMajorVersion   : Uint4B
   +0x11c OSMinorVersion   : Uint4B
   +0x120 OSBuildNumber    : Uint2B
   +0x122 OSCSDVersion     : Uint2B
   +0x124 OSPlatformId     : Uint4B
   +0x128 ImageSubsystem   : Uint4B
   +0x12c ImageSubsystemMajorVersion : Uint4B
   +0x130 ImageSubsystemMinorVersion : Uint4B
   +0x134 Padding4         : [4] UChar
   +0x138 ActiveProcessAffinityMask : Uint8B
   +0x140 GdiHandleBuffer  : [60] Uint4B
   +0x230 PostProcessInitRoutine : Ptr64     void 
   +0x238 TlsExpansionBitmap : Ptr64 Void
   +0x240 TlsExpansionBitmapBits : [32] Uint4B
   +0x2c0 SessionId        : Uint4B
   +0x2c4 Padding5         : [4] UChar
   +0x2c8 AppCompatFlags   : _ULARGE_INTEGER
   +0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER
   +0x2d8 pShimData        : Ptr64 Void
   +0x2e0 AppCompatInfo    : Ptr64 Void
   +0x2e8 CSDVersion       : _UNICODE_STRING
   +0x2f8 ActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
   +0x300 ProcessAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
   +0x308 SystemDefaultActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
   +0x310 SystemAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
   +0x318 MinimumStackCommit : Uint8B
   +0x320 SparePointers    : [4] Ptr64 Void
   +0x340 SpareUlongs      : [5] Uint4B
   +0x358 WerRegistrationData : Ptr64 Void
   +0x360 WerShipAssertPtr : Ptr64 Void
   +0x368 pUnused          : Ptr64 Void
   +0x370 pImageHeaderHash : Ptr64 Void
   +0x378 TracingFlags     : Uint4B
   +0x378 HeapTracingEnabled : Pos 0, 1 Bit
   +0x378 CritSecTracingEnabled : Pos 1, 1 Bit
   +0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
   +0x378 SpareTracingBits : Pos 3, 29 Bits
   +0x37c Padding6         : [4] UChar
   +0x380 CsrServerReadOnlySharedMemoryBase : Uint8B
   +0x388 TppWorkerpListLock : Uint8B
   +0x390 TppWorkerpList   : _LIST_ENTRY
   +0x3a0 WaitOnAddressHashTable : [128] Ptr64 Void
   +0x7a0 TelemetryCoverageHeader : Ptr64 Void
   +0x7a8 CloudFileFlags   : Uint4B
   +0x7ac CloudFileDiagFlags : Uint4B
   +0x7b0 PlaceholderCompatibilityMode : Char
   +0x7b1 PlaceholderCompatibilityModeReserved : [7] Char
   +0x7b8 LeapSecondData   : Ptr64 _LEAP_SECOND_DATA
   +0x7c0 LeapSecondFlags  : Uint4B
   +0x7c0 SixtySecondEnabled : Pos 0, 1 Bit
   +0x7c0 Reserved         : Pos 1, 31 Bits
   +0x7c4 NtGlobalFlag2    : Uint4B
```
</details>

# :+1: 参考链接
1. [anti-reverse-engineering-protection-techniques-to-use-before-releasing-software](https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software)
2. [How to Reverse Engineer Software (Windows) in a Right Way](https://www.apriorit.com/dev-blog/364-how-to-reverse-engineer-software-windows-in-a-right-way)
3. [opeenACE](http://www.openrce.org/articles/)