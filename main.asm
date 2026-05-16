format PE console
entry start

include 'win32ax.inc'

TH32CS_SNAPPROCESS = 2
MAX_PIDS = 256

section '.data' data readable writeable

    szTarget    db 'Jazz2_NonPlus.exe', 0
    szDetected  db 'Detected Jazz2_NonPlus.exe (PID: %u), patching...', 13, 10, 0
    szSuccess   db 'Patched successfully! Multiple instances enabled.', 13, 10, 13, 10, 0
    szFailed    db 'Patch failed, retrying...', 13, 10, 0
    szBanner    db 'Jazz2 Multi-Instance Patcher', 13, 10, 'Monitoring for Jazz2_NonPlus.exe...', 13, 10, 'Start the game now. Press Ctrl+C to stop monitoring.', 13, 10, 13, 10, 0

    targetAddress dd 0x0048B820
    patchByte     db 0xC3

    patchedPIDs   rd MAX_PIDS
    patchedCount  dd 0
    hStdOut       dd 0
    hSnapshot     dd 0
    oldProtect    dd 0
    bytesWritten  dd 0

section '.bss' data readable writeable

    pe  rb 296
    buf rb 128

section '.code' code readable executable


proc PatchFunction, processId
    locals
        local_hProcess dd ?
    endl

    invoke OpenProcess, PROCESS_VM_OPERATION or PROCESS_VM_WRITE or PROCESS_VM_READ, FALSE, [processId]
    test    eax, eax
    jz      .fail
    mov     [local_hProcess], eax

    invoke  VirtualProtectEx, [local_hProcess], [targetAddress], 1, PAGE_EXECUTE_READWRITE, oldProtect
    test    eax, eax
    jz      .closeAndFail

    invoke  WriteProcessMemory, [local_hProcess], [targetAddress], patchByte, 1, bytesWritten
    push    eax

    invoke  VirtualProtectEx, [local_hProcess], [targetAddress], 1, [oldProtect], oldProtect

    pop     eax
    invoke  CloseHandle, [local_hProcess]
    ret

.closeAndFail:
    invoke  CloseHandle, [local_hProcess]
.fail:
    xor     eax, eax
    ret
endp

proc MonitorAndPatch
    locals
        localIndex dd ?
    endl

    invoke  CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      .done

    mov     [hSnapshot], eax

    mov     dword [pe], 296

    invoke  Process32First, [hSnapshot], pe
    test    eax, eax
    jz      .close

.loop:
    invoke  lstrcmpiA, pe + 36, szTarget
    test    eax, eax
    jnz     .next

    mov     eax, dword [pe + 8]
    xor     ecx, ecx

.checkLoop:
    cmp     ecx, [patchedCount]
    jge     .notPatched
    cmp     [patchedPIDs + ecx*4], eax
    je      .next
    inc     ecx
    jmp     .checkLoop

.notPatched:
    invoke  wsprintf, buf, szDetected, dword [pe + 8]
    invoke  lstrlenA, buf
    invoke  WriteConsoleA, [hStdOut], buf, eax, bytesWritten, 0
    invoke  Sleep, 50
    stdcall PatchFunction, dword [pe + 8]
    
    test    eax, eax
    jz      .patchFailed

    mov     eax, [patchedCount]
    mov     ecx, dword [pe + 8]
    mov     [patchedPIDs + eax*4], ecx
    inc     dword [patchedCount]

    invoke  lstrlenA, szSuccess
    invoke  WriteConsoleA, [hStdOut], szSuccess, eax, bytesWritten, 0
    jmp     .next

.patchFailed:
    invoke  lstrlenA, szFailed
    invoke  WriteConsoleA, [hStdOut], szFailed, eax, bytesWritten, 0

.next:
    invoke  Process32Next, [hSnapshot], pe
    test    eax, eax
    jnz     .loop

.close:
    invoke  CloseHandle, [hSnapshot]

.done:
    ret
endp

start:
    invoke  GetStdHandle, STD_OUTPUT_HANDLE
    mov     [hStdOut], eax

    invoke  lstrlenA, szBanner
    invoke  WriteConsoleA, [hStdOut], szBanner, eax, bytesWritten, 0

.mainLoop:
    call    MonitorAndPatch
    invoke  Sleep, 100
    jmp     .mainLoop

section '.idata' import data readable

    library kernel32, 'kernel32.dll',\
            user32,   'user32.dll'

    import  kernel32,\
            OpenProcess,              'OpenProcess',\
            VirtualProtectEx,         'VirtualProtectEx',\
            WriteProcessMemory,       'WriteProcessMemory',\
            CloseHandle,              'CloseHandle',\
            CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot',\
            Process32First,           'Process32First',\
            Process32Next,            'Process32Next',\
            Sleep,                    'Sleep',\
            GetStdHandle,             'GetStdHandle',\
            WriteConsoleA,            'WriteConsoleA',\
            lstrcmpiA,                'lstrcmpiA',\
            lstrlenA,                 'lstrlenA'

    import  user32,\
            wsprintf,                 'wsprintfA'