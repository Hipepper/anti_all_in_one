# 🍳根据内核句柄反调试

##  OpenProcess()
可以使用`kernel32!OpenProcess()`来检测一些调试器，只用管理员权限用户组并且有调试权限的进程，才能通过`csrss.exe`调用成功。

```
typedef DWORD (WINAPI *TCsrGetProcessId)(VOID);

bool Check()
{   
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
        return false;
    
    TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfnCsrGetProcessId)
        return false;

    HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pfnCsrGetProcessId());
    if (hCsr != NULL)
    {
        CloseHandle(hCsr);
        return true;
    }        
    else
        return false;
}
```

## CreateFile()
当`CREATE_PROCESS_DEBUG_EVENT`事件发生时，被调试文件的句柄存储在`CREATEPROCESS_DEBUG_INFO`结构中。因此，调试器可以从此文件读取调试信息。如果调试器未关闭此句柄，则不会以独占访问方式打开文件。一些调试器可能会忘记关闭句柄。

这个技巧使用`kernel32！CreateFileW()（或kernel32！CreateFileA()`以独占方式打开当前进程的文件。如果调用失败，我们可以认为当前进程是在调试器存在的情况下运行的。
```
bool Check()
{
    CHAR szFileName[MAX_PATH];
    if (0 == GetModuleFileNameA(NULL, szFileName, sizeof(szFileName)))
        return false;
    
    return INVALID_HANDLE_VALUE == CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
}
```

## CloseHandle()
如果程序正在被调试，那么使用ntdll!NtClose() 或者 kernel32!CloseHandle()调用程序就会抛出异常`EXCEPTION_INVALID_HANDLE (0xC0000008)`。如果异常被接管，就代表有调试器：
```
bool Check()
{
    __try
    {
        CloseHandle((HANDLE)0xDEADBEEF);
        return false;
    }
    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
                ? EXCEPTION_EXECUTE_HANDLER 
                : EXCEPTION_CONTINUE_SEARCH)
    {
        return true;
    }
}
```

## LoadLibrary()

如果程序被调用到内存，文件句柄将会保存在[LOAD_DLL_DEBUG_INFO](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-load_dll_debug_info),所以同理我们直接去load某一个文件，并用`CreateFileA`打开，如果失败就代表被占用。
```
bool Check()
{
    CHAR szBuffer[] = { "calc.exe" };
    LoadLibraryA(szBuffer);
    return INVALID_HANDLE_VALUE == CreateFileA(szBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}
```

## NtQueryObject()
如果调试会话存在，会在内核中存在一个`debug object`结构体，使用`ntdll!NtQueryObject()`枚举内核结构体句柄，当然这个只能判断是不是存在调试器，不能判断正在被调试与否。🍑
```
typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfHandles;
    ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION
{
    ULONG NumberOfObjects;
    OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

typedef NTSTATUS (WINAPI *TNtQueryObject)(
    HANDLE                   Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID                    ObjectInformation,
    ULONG                    ObjectInformationLength,
    PULONG                   ReturnLength
);

enum { ObjectAllTypesInformation = 3 };

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

bool Check()
{
    bool bDebugged = false;
    NTSTATUS status;
    LPVOID pMem = nullptr;
    ULONG dwMemSize;
    POBJECT_ALL_INFORMATION pObjectAllInfo;
    PBYTE pObjInfoLocation;
    HMODULE hNtdll;
    TNtQueryObject pfnNtQueryObject;
    
    hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
        return false;
        
    pfnNtQueryObject = (TNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    if (!pfnNtQueryObject)
        return false;

    status = pfnNtQueryObject(
        NULL,
        (OBJECT_INFORMATION_CLASS)ObjectAllTypesInformation,
        &dwMemSize, sizeof(dwMemSize), &dwMemSize);
    if (STATUS_INFO_LENGTH_MISMATCH != status)
        goto NtQueryObject_Cleanup;

    pMem = VirtualAlloc(NULL, dwMemSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pMem)
        goto NtQueryObject_Cleanup;

    status = pfnNtQueryObject(
        (HANDLE)-1,
        (OBJECT_INFORMATION_CLASS)ObjectAllTypesInformation,
        pMem, dwMemSize, &dwMemSize);
    if (!SUCCEEDED(status))
        goto NtQueryObject_Cleanup;

    pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMem;
    pObjInfoLocation = (PBYTE)pObjectAllInfo->ObjectTypeInformation;
    for(UINT i = 0; i < pObjectAllInfo->NumberOfObjects; i++)
    {

        POBJECT_TYPE_INFORMATION pObjectTypeInfo =
            (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

        if (wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer) == 0)
        {
            if (pObjectTypeInfo->TotalNumberOfObjects > 0)
                bDebugged = true;
            break;
        }

        // Get the address of the current entries
        // string so we can find the end
        pObjInfoLocation = (PBYTE)pObjectTypeInfo->TypeName.Buffer;

        // Add the size
        pObjInfoLocation += pObjectTypeInfo->TypeName.Length;

        // Skip the trailing null and alignment bytes
        ULONG tmp = ((ULONG)pObjInfoLocation) & -4;

        // Not pretty but it works
        pObjInfoLocation = ((PBYTE)tmp) + sizeof(DWORD);
    }

NtQueryObject_Cleanup:
    if (pMem)
        VirtualFree(pMem, 0, MEM_RELEASE);

    return bDebugged;
}
```

## 🍺🍺对抗方法
最简单的方式就是分析到的时候nop掉，如果你想写一个反反调试方案，下面就是需要hook的 toDo:
1. `ntdll!OpenProcess`：如果第三个参数是csrss.exe进程的句柄，则返回NULL。
2. `ntdll!NtClose`:
3. `ntdll!NtQueryObject:`
其他函数只能分析的时候nop掉。


# 🍭根据异常反调试
> 制作异常，来看程序的状态

## 1. UnhandledExceptionFilter()
如果程序抛出异常但是没有异常接管，那么就会调用`kernel32!UnhandledExceptionFilter()`,所以可以注册一个异常处理来检查状态：

x86  FASM
```
include 'win32ax.inc'

.code

start:
        jmp begin

not_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Not Debugged","",MB_OK
        invoke  ExitProcess,0

begin:
        invoke SetUnhandledExceptionFilter, not_debugged
        int  3  # 如果程序自己处理了就没有被调试
        jmp  being_debugged

being_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Debugged","",MB_OK
        invoke  ExitProcess,0

.end start
```

```
LONG UnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip \xCC\xEB\x??
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool Check()
{
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)UnhandledExceptionFilter);
    __asm
    {
        int 3                      // CC
        jmp near being_debugged    // EB ??
    }
    bDebugged = false;

being_debugged:
    return bDebugged;
}

```


## 2.RaiseException()
`DBC_CONTROL_C  DBG_RIPEVENT`异常只能被调试器接管，所以用`kernel32!RaiseException()`抛出异常，如果没进入到我们的处理程序就是被调试了

```
bool Check()
{
    __try
    {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except(DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER 
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}
```

## 3. 异常处理嵌套

你懂的，一层层嵌套隐藏真正代码，只是一个思路：
```
#include <Windows.h>

void MaliciousEntry()
{
    // ...
}

void Trampoline2()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MaliciousEntry();
    }
}

void Trampoline1()
{
    __try 
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Trampoline2();
    }
}

int main(void)
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    {
        Trampoline1();
    }

    return 0;
}
```
```
#include <Windows.h>

PVOID g_pLastVeh = nullptr;

void MaliciousEntry()
{
    // ...
}

LONG WINAPI ExeptionHandler2(PEXCEPTION_POINTERS pExceptionInfo)
{
    MaliciousEntry();
    ExitProcess(0);
}

LONG WINAPI ExeptionHandler1(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (g_pLastVeh)
    {
        RemoveVectoredExceptionHandler(g_pLastVeh);
        g_pLastVeh = AddVectoredExceptionHandler(TRUE, ExeptionHandler2);
        if (g_pLastVeh)
            __asm int 3;
    }
    ExitProcess(0);
}


int main(void)
{
    g_pLastVeh = AddVectoredExceptionHandler(TRUE, ExeptionHandler1);
    if (g_pLastVeh)
        __asm int 3;

    return 0;
}
```

# 🚲根据CPU滴答
> 主要原理就是程序运行的时间和调试时指令运行时间的差异来判断是否调试
当在调试器中跟踪进程时，指令和执行之间存在延迟。可以使用几种方法测量代码某些部分之间的“本地”延迟，并将其与实际延迟进行比较。

你也可以自己设置一个时间上限，在 `... ...`位置放入一个函数，并检测运行时间做diff。
## 1.😁RDPMC/RDTSC
这些指令要求在CR4寄存器中设置标志PCE，并且 `RDPMC` 指令只能在内核，`RDTSC`是在用户层上。
```
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor  ecx, ecx
        rdpmc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... ....
    __asm
    {
        xor  ecx, ecx
        rdpmc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}


bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... ....
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed; // 计算延迟
}
```
## 2. 😎GetLocalTime()

```
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    // ... ...
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}

```
## 3.GetSystemTime()
```
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetSystemTime(&stStart);
    // ... ...
    GetSystemTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
```
## 4.GetTickCount()
```
bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = GetTickCount();
    // ... some work
    return (GetTickCount() - dwStart) > dwNativeElapsed;
}
```
## 5.ZwGetTickCount() / KiGetTickCount()

这两个函数仅在内核模式下使用。和用户模式一样，都从`KUSER_SHARED_DATA `页面中获取数据，此页面以只读方式映射到虚拟地址的用户模式范围中，并在内核范围中读写。系统时钟滴答更新系统时间，该时间直接存储在此页面中。

`ZwGetTickCount()` 和 `GetTickCount()` 使用方式一样.  `KiGetTickCount()` 比调用 `ZwGetTickCount()` 快, 但是比直接读取 `KUSER_SHARED_DATA` 页面慢。

```
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        int  2ah
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... ...
    __asm
    {
        int  2ah
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}
```

## 6.QueryPerformanceCounter()
```
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    LARGE_INTEGER liStart, liEnd;
    QueryPerformanceCounter(&liStart);
    // ......
    QueryPerformanceCounter(&liEnd);
    return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
}
```

## 7.timeGetTime()
```
bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = timeGetTime();
    // ... some work
    return (timeGetTime() - dwStart) > dwNativeElapsed;
}
```