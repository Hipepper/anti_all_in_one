<!--
 * @Author: jentle
 * @Description: 
 * @Date: 2022-11-07 14:22:49
 * @LastEditors: jentle
 * @LastEditTime: 2022-11-07 15:37:18
-->
# 进程内存anti 😎
> 检查断点，检查线程上下文，检查anti补丁等..

## 1. 断点
我们可以检查进程内存并在代码中搜索软件断点，或者检查CPU调试寄存器以确定是否设置了硬件断点。

如果对 0xCC搜索，也就是INT 3,可能会有很大误报率，因为也有可能是合法进程的一些指令：
```

bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
{
    PBYTE pBytes = (PBYTE)pMemory; 
    for (SIZE_T i = 0; ; i++)
    {
        // Break RET (0xC3) 如果不知道函数大小
        if (((nMemorySize > 0) && (i >= nMemorySize)) ||
            ((nMemorySize == 0) && (pBytes[i] == 0xC3)))
            break;

        if (pBytes[i] == cByte)
            return true;
    }
    return false;
}

bool IsDebugged()
{
    PVOID functionsToCheck[] = {
        &Function1,
        &Function2,
        &Function3,
    };
    for (auto funcAddr : functionsToCheck)
    {
        if (CheckForSpecificByte(0xCC, funcAddr))
            return true;
    }
    return false;
}
```

### F8 跳过🏓
调试器允许您跳过函数调用，也就是步过。在这种情况下，调试器隐式地在调用后的指令上设置软件断点（即被调用函数的返回地址）。
为了检测是否有人试图跳过函数，我们可以检查返回地址处的内存的第一个字节。如果软件断点（0xCC）位于返回地址，我们可以使用其他指令（例如NOP）对其进行修补。它很可能会破坏代码并使进程崩溃。另一方面，我们可以用一些有意义的代码来修补返回地址，而不是NOP，并更改程序的控制流。

这种检测出存在0xCC就达到部门，如果想path的话容易程序崩溃，可以世界path：
```
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

void foo()
{
    // ...
    
    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC) // int 3
    {
        DWORD dwOldProtect;
        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            *(PBYTE)pRetAddress = 0x90; // nop
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }
    
    // ...
}
```
也可以使用`ReadFile(),WriteProcessMemory(),Toolhelp32ReadProcessMemory()`对目标进程进行修复跳转。🥇



## 2.✨内存断点

在od中使用保护页（ guard pages）实现内存断点，保护页为内存页访问提供一次报警。保护页被执行时候，会抛出`STATUS_GUARD_PAGE_VIOLATION `异常，PAGE_GUARD 可以通过`kernel32!VirtualAlloc(), kernel32!VirtualAllocEx(), kernel32!VirtualProtect(), kernel32!VirtualProtectEx()`函数创建。

我们可以滥用调试器实现内存断点的方式来检查程序是否在调试器下执行。我们可以分配一个只包含一个字节0xC3的可执行缓冲区，它代表RET指令。然后，我们将此缓冲区标记为保护页，将处理调试器存在情况的地址推送到堆栈，并跳转到分配的缓冲区，然后RET执行，我们会找到我们推送到堆栈的地址。如果程序在没有调试器的情况下执行，我们将得到一个异常处理程序。
```
bool IsDebugged()
{
    DWORD dwOldProtect = 0;
    SYSTEM_INFO SysInfo = { 0 };

    GetSystemInfo(&SysInfo);
    PVOID pPage = VirtualAlloc(NULL, SysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (NULL == pPage)
        return false; 

    PBYTE pMem = (PBYTE)pPage;
    *pMem = 0xC3; 

    //  guard page 设置    
    if (!VirtualProtect(pPage, SysInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect))
        return false;

    __try
    {
        __asm
        {
            mov eax, pPage
            push mem_bp_being_debugged
            jmp eax
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        VirtualFree(pPage, NULL, MEM_RELEASE);
        return false;
    }

mem_bp_being_debugged:
    VirtualFree(pPage, NULL, MEM_RELEASE);
    return true;
```

## 3. 内存断点
可以从线程上下文中检索调试寄存器DR0、DR1、DR2和DR3。如果它们包含非零值，则可能意味着进程在调试器下执行，并且设置了硬件断点。
```
bool IsDebugged()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT)); 
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 

    if(!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
```