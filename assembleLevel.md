<!--
 * @Author: jentle
 * @Description: 
 * @Date: 2022-10-26 17:30:21
 * @LastEditors: jentle
 * @LastEditTime: 2022-10-26 19:18:47
-->
## :star: professionAdd: 汇编级别
> 以下技术旨在根据CPU执行特定指令时，调试器的行为来检测调试器是否存在。
> 你可以将这篇作为 [basicKnow](https://github.com/Hipepper/anti_all_in_one/blob/main/basicKnow.md) 部分的补充阅读

***

### 一、:sweat_smile:INT 3 
指令INT3是用作软件断点的中断。在没有调试器的情况下，在到达INT3指令后，将生成异常`EXCEPTION_BREAKPOINT (0x80000003)`，并将调用异常处理程序。如果存在调试器，则不会将控制权赋予异常处理程序。
```
bool IsDebugged()
{
    __try
    {
        __asm int 3;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```
除了 INT 3指令的简短形式`0xCC`之外，该指令还有一种长形式：`CD 03`。

当异常`EXCEPTION_BREAKPOINT `发生时，Windows将EIP寄存器递减到`0xCC`操作码的假定位置，并将控制权传递给异常处理程序。对于INT3指令的长形式，EIP将指向指令的中间（0x03偏移字节处）。因此，如果我们想在INT3指令之后继续执行，就应该在异常处理程序中编辑EIP（否则我们很可能会得到`EXCEPTION_ACCESS_VIOLATION `异常）。如果没有，我们可以忽略指令指针的修改。
```
bool g_bDebugged = false;

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
    g_bDebugged = code != EXCEPTION_BREAKPOINT;
    return EXCEPTION_EXECUTE_HANDLER;
}

bool IsDebugged()
{
    __try
    {
        __asm __emit(0xCD);
        __asm __emit(0x03);
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation()))
    {
        return g_bDebugged;
    }
}
```

### 二、:shit: INT 2D
跟`INT 3`一样，该指令也会触发`EXCEPTION_BREAKPOINT `,但对于INT2D，Windows使用EIP寄存器作为异常地址，然后递增EIP寄存器值。在执行INT2D时，Windows还检查EAX寄存器的值。如果为1、3或4，或在Vista+上为5，则异常地址将增加1。
对于一些调试器可能会崩溃，当EIP用作异常处理地址之后，`INT 2D`指令后的代码将会被跳过，可能跳入到一些非法指令处。
在本例中，我们将一个字节的`NOP`指令放在INT2D之后，以便在任何情况下跳过它都不影响。如果程序在没有调试器的情况下执行，则控制权将传递给异常处理程序。
```
bool IsDebugged()
{
    __try
    {
        __asm xor eax, eax;
        __asm int 0x2d;
        __asm nop;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```

### 三、:smile: DebugBreak

如DebugBreak文档中所述，“`DebugBreak`导致当前进程中发生断点异常。这允许调用线程向调试器发出信号以处理异常”。
如果程序在没有调试器的情况下执行，则控制权将传递给异常处理程序。否则，调试器将拦截执行。
```
bool IsDebugged()
{
    __try
    {
        DebugBreak();
    }
    __except(EXCEPTION_BREAKPOINT)
    {
        return false;
    }
    
    return true;
}
```
### 四、ICE
“ICE”是英特尔的一条未经证明的指令。它的操作码是`0xF1`:fire:。它可以用来检测程序是否被跟踪。

如果执行ICE指令，将引发`EXCEPTION_SINGLE_STEP（0x8000004）`异常。
但是，如果程序已经被跟踪调试，调试器会将此异常视为通过在`Flags`寄存器中设置`SingleStep`位来执行指令而生成的正常异常。因此，在调试器下，不会调用异常处理程序，ICE指令后将继续执行。
```
bool IsDebugged()
{
    __try
    {
        __asm __emit 0xF1;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```

### 五、堆栈寄存器
跟踪以下汇编指令序列：
```
push ss 
pop ss 
pushf
```
如果在调试器中单步经过此代码，:thinking:[Trap标志位](https://en.wikipedia.org/wiki/Trap_flag) 将会被设置，正常情况下，调试器在每一个调试事件传送完后清理 TRAP 标志，并且不可见。但是只要事前保存`EFLAGS`到堆栈，就可以检查 Tarp 是否更改。
```
bool IsDebugged()
{
    bool bTraced = false;

    __asm
    {
        push ss
        pop ss
        pushf
        test byte ptr [esp+1], 1
        jz movss_not_being_debugged
    }

    bTraced = true;

movss_not_being_debugged:

    __asm popf;

    return bTraced;
}
```
### 六、指令计数
> 滥用调试器`EXCEPTION_SINGLE_STEP`异常处理方式

这个技巧的思想是按照预定义的顺序为每条指令设置硬件断点。执行带有硬件断点的指令会引发`EXCEPTION_SINGLE_STEP`异常，并被异常处理链捕获。在异常处理程序中，我们设置一个寄存器，该寄存器充当指令计数器（在本例中为EAX）和指令指针EIP的角色，以将控制权传递给序列中的下一条指令。因此，每次将控制权传递到序列中的下一条指令时，:thumbsup:都会引发异常并递增计数器。当指定的序列执行完后，比较指令数和计数器，不一样就代表有调试器存在：
<details>

<summary>代码片段</summary>

```
#include "hwbrk.h"

static LONG WINAPI InstructionCountingExeptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        pExceptionInfo->ContextRecord->Eax += 1;
        pExceptionInfo->ContextRecord->Eip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(naked) DWORD WINAPI InstructionCountingFunc(LPVOID lpThreadParameter)
{
    __asm
    {
        xor eax, eax
        nop
        nop
        nop
        nop
        cmp al, 4
        jne being_debugged
    }

    ExitThread(FALSE);

being_debugged:
    ExitThread(TRUE);
}

bool IsDebugged()
{
    PVOID hVeh = nullptr;
    HANDLE hThread = nullptr;
    bool bDebugged = false;

    __try
    {
        hVeh = AddVectoredExceptionHandler(TRUE, InstructionCountingExeptionHandler);
        if (!hVeh)
            __leave;

        hThread = CreateThread(0, 0, InstructionCountingFunc, NULL, CREATE_SUSPENDED, 0);
        if (!hThread)
            __leave;

        PVOID pThreadAddr = &InstructionCountingFunc;
        // Fix thread entry address if it is a JMP stub (E9 XX XX XX XX)
        if (*(PBYTE)pThreadAddr == 0xE9)
            pThreadAddr = (PVOID)((DWORD)pThreadAddr + 5 + *(PDWORD)((PBYTE)pThreadAddr + 1));

        for (auto i = 0; i < m_nInstructionCount; i++)
            m_hHwBps[i] = SetHardwareBreakpoint(
                hThread, HWBRK_TYPE_CODE, HWBRK_SIZE_1, (PVOID)((DWORD)pThreadAddr + 2 + i));

        ResumeThread(hThread);
        WaitForSingleObject(hThread, INFINITE);

        DWORD dwThreadExitCode;
        if (TRUE == GetExitCodeThread(hThread, &dwThreadExitCode))
            bDebugged = (TRUE == dwThreadExitCode);
    }
    __finally
    {
        if (hThread)
            CloseHandle(hThread);

        for (int i = 0; i < 4; i++)
        {
            if (m_hHwBps[i])
                RemoveHardwareBreakpoint(m_hHwBps[i]);
        }

        if (hVeh)
            RemoveVectoredExceptionHandler(hVeh);
    }

    return bDebugged;
}
```
</details>

### 七、POPFD 和 Trap 标志

设置 Trap 标志时，将引发异常 `SINGLE_STEP`。但是，如果我们跟踪调试代码，Trap 标志将被调试器清除，因此我们不会看到异常。
```
bool IsDebugged()
{
    __try
    {
        __asm
        {
            pushfd
            mov dword ptr [esp], 0x100
            popfd
            nop
        }
        return true;
    }
    __except(GetExceptionCode() == EXCEPTION_SINGLE_STEP
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_EXECUTION)
    {
        return false;
    }
}
```

### 八、:beer: 指令前缀（OllyDbg v1.10）
>  Instruction Prefixes

在`"PUSHFD"`，前面加上`REP`指令前缀，od识别不了。
在下面的例子中，如果在od调试器，当步入到 0xF3 时，我们会直接跳到 try 的末尾。调试器直接跳过前缀，并把控制权交给 INT1 指令。

```
bool IsDebugged()
{
    __try
    {
        // 0xF3 0x64  PREFIX REP:
        __asm __emit 0xF3
        __asm __emit 0x64
        // One byte INT 1
        __asm __emit 0xF1
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```

### 参考资料
1. [前缀demo](https://gist.github.com/trietptm/4472568)
2. [AntiCheckPoint](https://anti-debug.checkpoint.com/)
3. [前缀指令](https://blog.csdn.net/Apollon_krj/article/details/77508073)