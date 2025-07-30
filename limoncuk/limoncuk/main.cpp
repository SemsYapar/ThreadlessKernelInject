#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define IOCTL_IAT_PATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define MAX_PIDS 1024

typedef struct _INJECTION_DATA {
    int pid;
    char functionName[256];
} INJECTION_DATA;

int GetPIDsByProcessName(const char* targetProcessName, DWORD* pidArray, int maxCount) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    int count = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (strcmp(pe32.szExeFile, targetProcessName) == 0) {
            if (count < maxCount) {
                pidArray[count++] = pe32.th32ProcessID;
            }
            else {
                break;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return count;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Argumanlaaaaaarr!");
        return 1;
    }
    const char* importedFunctionName = argv[2];
    HANDLE hDevice = CreateFile("\\\\.\\IATPatch", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Driver not found. errrocode: %d\n",GetLastError());
        return 1;
    }
    DWORD pids[MAX_PIDS];
    int pids_c = GetPIDsByProcessName(argv[1], pids, MAX_PIDS);
    for (int i = 0; i < pids_c; i++) {
        INJECTION_DATA data;
        data.pid = pids[i];
        memset(data.functionName, 0, sizeof(data.functionName));
        memcpy(data.functionName, importedFunctionName, min(strlen(importedFunctionName), sizeof(data.functionName) - 1));
        DWORD ret;
        BOOL ok = DeviceIoControl(hDevice, IOCTL_IAT_PATCH, &data, sizeof(data), NULL, 0, &ret, NULL);
        if (ok) {
            printf("IAT patch request sent for pid: %d\n",pids[i]);
        }
        else {
            printf("IOCTL failed: %lu\n", GetLastError());
        }
    }
    CloseHandle(hDevice);

    return 0;
}
