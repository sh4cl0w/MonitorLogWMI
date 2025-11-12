#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Provider GUID của Microsoft-Windows-WMI-Activity
static const GUID WMI_PROVIDER_GUID =
{ 0x1418EF04, 0xB0B4, 0x4623, { 0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA } };

static volatile BOOL g_Stop = FALSE;
static HANDLE g_hThread = NULL;
static FILE* g_LogFile = NULL;
static CRITICAL_SECTION g_LogCriticalSection;

// Cấu hình log rotation
#define MAX_LOG_FILE_SIZE (10 * 1024 * 1024) // 10MB
#define LOG_ROTATION_COUNT 4

// === Khởi tạo log với rotation ===
BOOL InitializeLogSystem()
{
    InitializeCriticalSection(&g_LogCriticalSection);

    // Kiểm tra kích thước file log hiện tại
    struct _stat fileStat;
    if (_stat("C:\\Windows\\Temp\\WMI_Monitor.log", &fileStat) == 0 &&
        fileStat.st_size > MAX_LOG_FILE_SIZE)
    {
        

        // Thực hiện log rotation
        for (int i = LOG_ROTATION_COUNT - 1; i > 0; i--)
        {
            char oldName[MAX_PATH], newName[MAX_PATH];
            sprintf(oldName, "C:\\Windows\\Temp\\WMI_Monitor.%d.log", i - 1);
            sprintf(newName, "C:\\Windows\\Temp\\WMI_Monitor.%d.log", i);

            // Xóa file cũ nếu tồn tại
            DeleteFileA(newName);
            // Di chuyển file cũ sang version mới
            MoveFileA(oldName, newName);
        }

        // Di chuyển file log hiện tại thành version 0
        MoveFileA("C:\\Windows\\Temp\\WMI_Monitor.log",
            "C:\\Windows\\Temp\\WMI_Monitor.0.log");
    }

    g_LogFile = fopen("C:\\Windows\\Temp\\WMI_Monitor.log", "a");
    if (!g_LogFile)
    {
        printf("[-] Khong the mo file log de ghi.\n");
        return FALSE;
    }

    return TRUE;
}

// === Ghi log an toàn với critical section ===
void LogMessage(const char* fmt, ...)
{
    EnterCriticalSection(&g_LogCriticalSection);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    if (g_LogFile)
    {
        // Kiểm tra kích thước file trước khi ghi
        long currentSize = ftell(g_LogFile);
        if (currentSize > MAX_LOG_FILE_SIZE)
        {
            // Đóng file hiện tại
            fclose(g_LogFile);

            // Thực hiện log rotation
            for (int i = LOG_ROTATION_COUNT - 1; i > 0; i--)
            {
                char oldName[MAX_PATH], newName[MAX_PATH];
                sprintf(oldName, "C:\\Windows\\Temp\\WMI_Monitor.%d.log", i - 1);
                sprintf(newName, "C:\\Windows\\Temp\\WMI_Monitor.%d.log", i);

                DeleteFileA(newName);
                MoveFileA(oldName, newName);
            }

            // Di chuyển file log hiện tại
            MoveFileA("C:\\Windows\\Temp\\WMI_Monitor.log",
                "C:\\Windows\\Temp\\WMI_Monitor.0.log");

            // Mở file log mới
            g_LogFile = fopen("C:\\Windows\\Temp\\WMI_Monitor.log", "a");
            if (!g_LogFile)
            {
                printf("[-] Khong the tao file log moi sau rotation.\n");
                LeaveCriticalSection(&g_LogCriticalSection);
                return;
            }
        }

        vfprintf(g_LogFile, fmt, args);
        fflush(g_LogFile);
    }
    va_end(args);

    LeaveCriticalSection(&g_LogCriticalSection);
}

// === Ghi log Unicode ===
void LogMessageW(const wchar_t* fmt, ...)
{
    EnterCriticalSection(&g_LogCriticalSection);

    va_list args;
    va_start(args, fmt);
    vwprintf(fmt, args);
    if (g_LogFile)
    {
        vfwprintf(g_LogFile, fmt, args);
        fflush(g_LogFile);
    }
    va_end(args);

    LeaveCriticalSection(&g_LogCriticalSection);
}

// === Hàm callback được gọi khi có sự kiện mới ===
VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord)
{
    EVENT_HEADER* hdr = &pEventRecord->EventHeader;
    USHORT eventId = hdr->EventDescriptor.Id;
    ULONGLONG timestamp = hdr->TimeStamp.QuadPart;
    if (eventId == 100) {
        return; // Không log event nội bộ debug
    }
    FILETIME ft;
    SYSTEMTIME stUTC, stLocal;
    ft.dwLowDateTime = (DWORD)timestamp;
    ft.dwHighDateTime = (DWORD)(timestamp >> 32);
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    LogMessage("--------------------------------------------------------\n");
    LogMessage("<Event>\n");
    LogMessage("  <System>\n");
    LogMessage("    <Provider Name=\"Microsoft-Windows-WMI-Activity\" />\n");
    LogMessage("    <EventID>%hu</EventID>\n", eventId);
    LogMessage("    <Version>%hu</Version>\n", hdr->EventDescriptor.Version);
    LogMessage("    <Level>%hu</Level>\n", hdr->EventDescriptor.Level);
    LogMessage("    <Task>%hu</Task>\n", hdr->EventDescriptor.Task);
    LogMessage("    <Opcode>%hu</Opcode>\n", hdr->EventDescriptor.Opcode);
    LogMessage("    <Keywords>0x%llx</Keywords>\n", hdr->EventDescriptor.Keyword);
    LogMessage("    <ProcessID>%lu</ProcessID>\n", hdr->ProcessId);
    LogMessage("    <ThreadID>%lu</ThreadID>\n", hdr->ThreadId);
    LogMessage("    <TimeCreated SystemTime=\"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ\" />\n",
        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond, stLocal.wMilliseconds);
    LogMessage("  </System>\n");

    PTRACE_EVENT_INFO pInfo = NULL;
    ULONG bufferSize = 0;
    ULONG status = TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER)
    {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize);
        if (status == ERROR_SUCCESS)
        {
            LogMessage("  <EventData>\n");

            DWORD propCount = pInfo->TopLevelPropertyCount;
            for (DWORD i = 0; i < propCount; i++)
            {
                PROPERTY_DATA_DESCRIPTOR desc = { 0 };
                desc.PropertyName = (ULONGLONG)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
                desc.ArrayIndex = ULONG_MAX;

                WCHAR name[256] = { 0 };
                WCHAR value[1024] = { 0 };
                wcscpy(name, (WCHAR*)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset));

                ULONG size = sizeof(value);
                status = TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, size, (PBYTE)value);
                if (status == ERROR_SUCCESS)
                {
                    if (wcslen(value) > 0)
                        LogMessageW(L"    <Data Name=\"%s\">%s</Data>\n", name, value);
                    else
                        LogMessageW(L"    <Data Name=\"%s\" />\n", name);
                }
                else
                {
                    LogMessageW(L"    <Data Name=\"%s\">(unavailable)</Data>\n", name);
                }
            }

            LogMessage("  </EventData>\n");
        }
        free(pInfo);
    }

    LogMessage("</Event>\n");
}

// === Thread chính đọc ETW ===
DWORD WINAPI EtwMonitorThread(LPVOID lpParam)
{
    TRACEHANDLE hTrace = 0;
    EVENT_TRACE_LOGFILEA log = { 0 };

    log.LoggerName = "CyradarWMITrace";
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = (PEVENT_RECORD_CALLBACK)EventRecordCallback;

    hTrace = OpenTraceA(&log);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE)
    {
        LogMessage("[-] OpenTrace failed: %lu\n", GetLastError());
        return 1;
    }

    ULONG status = ProcessTrace(&hTrace, 1, 0, 0);
    if (status != ERROR_SUCCESS)
        LogMessage("[-] ProcessTrace stopped (code %lu)\n", status);

    CloseTrace(hTrace);
    return 0;
}

// === Tạo session và bật provider ===
BOOL EnableWmiProvider()
{
    TRACEHANDLE hSession = 0;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(pProps, bufferSize);

    pProps->Wnode.BufferSize = bufferSize;
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceA(&hSession, "CyradarWMITrace", pProps);
    if (status != ERROR_SUCCESS)
    {
        if (status == ERROR_ALREADY_EXISTS)
        {
            LogMessage("[!] Session da ton tai. dang xoa session cu...\n");
            ControlTraceA(0, "CyradarWMITrace", pProps, EVENT_TRACE_CONTROL_STOP);
            status = StartTraceA(&hSession, "CyradarWMITrace", pProps);
        }
    }

    if (status != ERROR_SUCCESS)
    {
        LogMessage("[-] StartTrace failed: %lu\n", status);
        free(pProps);
        return FALSE;
    }

    status = EnableTraceEx2(
        hSession,
        &WMI_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 0, 0, NULL);

    if (status != ERROR_SUCCESS)
    {
        LogMessage("[-] EnableTraceEx2 failed: %lu\n", status);
        ControlTraceA(hSession, "CyradarWMITrace", pProps, EVENT_TRACE_CONTROL_STOP);
        free(pProps);
        return FALSE;
    }

    LogMessage("[+] Provider Microsoft-Windows-WMI-Activity enabled.\n");
    free(pProps);
    return TRUE;
}

// === Dừng session ===
void StopTraceSession()
{
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(pProps, bufferSize);
    pProps->Wnode.BufferSize = bufferSize;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceA(0, "CyradarWMITrace", pProps, EVENT_TRACE_CONTROL_STOP);
    free(pProps);

    LogMessage("[*] ETW session da duoc xoa va dung.\n");
}

// === Xử lý Ctrl+C ===
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    if (fdwCtrlType == CTRL_C_EVENT)
    {
        LogMessage("\n[!] nhan Ctrl+C de dung theo doi...\n");
        g_Stop = TRUE;
        StopTraceSession();

        if (g_hThread)
            TerminateThread(g_hThread, 0);

        if (g_LogFile)
        {
            LogMessage("[*] Dong file log.\n");
            fclose(g_LogFile);
            g_LogFile = NULL;
        }

        DeleteCriticalSection(&g_LogCriticalSection);
        ExitProcess(0);
        return TRUE;
    }
    return FALSE;
}

int main()
{
    printf("=== ETW WMI Activity Monitor (with Log Rotation) ===\n");

    
    if (!InitializeLogSystem())
    {
        printf("[-] Khong the khoi tao he thong log.\n");
        return 1;
    }

    LogMessage("========== BAT DAU MONITOR WMI ==========\n");
    LogMessage("[*] Log rotation: 100MB, giu lai %d file log cu\n", LOG_ROTATION_COUNT);

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    if (!EnableWmiProvider())
    {
        LogMessage("[-] Khong the bat provider.\n");
        fclose(g_LogFile);
        DeleteCriticalSection(&g_LogCriticalSection);
        return 1;
    }

    g_hThread = CreateThread(NULL, 0, EtwMonitorThread, NULL, 0, NULL);
    if (!g_hThread)
    {
        LogMessage("[-] Khong the tao thread monitor.\n");
        StopTraceSession();
        fclose(g_LogFile);
        DeleteCriticalSection(&g_LogCriticalSection);
        return 1;
    }

    LogMessage("    Nhan Ctrl+C de dung va xoa session.\n");

    WaitForSingleObject(g_hThread, INFINITE);

    StopTraceSession();

    if (g_LogFile)
    {
        LogMessage("========== KET THUC MONITOR ==========\n");
        fclose(g_LogFile);
    }

    DeleteCriticalSection(&g_LogCriticalSection);

    return 0;
}