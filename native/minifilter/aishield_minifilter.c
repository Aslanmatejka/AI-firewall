/* AI Firewall minifilter — Phase 3 with file blocking + comm port. */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "aishield_protocol.h"

#define AISHIELD_PORT_NAME L"\\AiShieldMinifilterPort"

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
AISHIELD_POLICY_CACHE gPolicyCache = { 0 };

static KSPIN_LOCK gPolicyLock;
static BOOLEAN gLockInit = FALSE;

NTSTATUS AiShieldPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

NTSTATUS AiShieldPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

static NTSTATUS AiShieldConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
);

static VOID AiShieldDisconnectNotify(_In_opt_ PVOID ConnectionPortCookie);

static NTSTATUS AiShieldMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

static BOOLEAN AiShieldIsAiProcess(_In_ ULONG Pid, _Out_opt_ PUNICODE_STRING AppNameOut);
static BOOLEAN AiShieldMatchProtectedPath(_In_ PUNICODE_STRING Path, _Out_ PULONG PolicyOut);
static NTSTATUS AiShieldQueryUserMode(_In_ PUNICODE_STRING Path, _In_ ULONG Pid, _In_ PUNICODE_STRING AppName, _In_ ULONG FolderPolicy, _Out_ PULONG DecisionOut);

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, AiShieldPreCreate, AiShieldPostCreate },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0, NULL,
    Callbacks,
    AiShieldInstanceSetup,
    AiShieldInstanceTeardownStart,
    AiShieldMinifilterUnload,
    NULL, NULL, NULL, NULL
};

NTSTATUS AiShieldInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

VOID AiShieldInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);
}

static BOOLEAN
AiShieldIsAiProcess(_In_ ULONG Pid, _Out_opt_ PUNICODE_STRING AppNameOut)
{
    ULONG i;
    KIRQL irql;

    KeAcquireSpinLock(&gPolicyLock, &irql);
    for (i = 0; i < gPolicyCache.Sync.AiProcessCount && i < AISHIELD_MAX_AI_PROCS; i++) {
        if (gPolicyCache.Sync.AiProcesses[i].Pid == Pid) {
            if (AppNameOut != NULL) {
                RtlInitUnicodeString(AppNameOut, gPolicyCache.Sync.AiProcesses[i].AppName);
            }
            KeReleaseSpinLock(&gPolicyLock, irql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&gPolicyLock, irql);
    return FALSE;
}

static BOOLEAN
AiShieldMatchProtectedPath(_In_ PUNICODE_STRING Path, _Out_ PULONG PolicyOut)
{
    ULONG i;
    KIRQL irql;
    UNICODE_STRING folderPath;

    if (Path == NULL || PolicyOut == NULL) {
        return FALSE;
    }

    KeAcquireSpinLock(&gPolicyLock, &irql);
    for (i = 0; i < gPolicyCache.Sync.FolderCount && i < AISHIELD_MAX_FOLDERS; i++) {
        RtlInitUnicodeString(&folderPath, gPolicyCache.Sync.Folders[i].Path);
        if (RtlPrefixUnicodeString(&folderPath, Path, TRUE)) {
            *PolicyOut = gPolicyCache.Sync.Folders[i].Policy;
            KeReleaseSpinLock(&gPolicyLock, irql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&gPolicyLock, irql);
    return FALSE;
}

static NTSTATUS
AiShieldQueryUserMode(
    _In_ PUNICODE_STRING Path,
    _In_ ULONG Pid,
    _In_ PUNICODE_STRING AppName,
    _In_ ULONG FolderPolicy,
    _Out_ PULONG DecisionOut
)
{
    UCHAR msgBuf[sizeof(AISHIELD_MSG_HEADER) + sizeof(AISHIELD_FILE_QUERY)];
    PAISHIELD_MSG_HEADER hdr = (PAISHIELD_MSG_HEADER)msgBuf;
    PAISHIELD_FILE_QUERY query = (PAISHIELD_FILE_QUERY)(msgBuf + sizeof(AISHIELD_MSG_HEADER));
    AISHIELD_FILE_RESPONSE response;
    LARGE_INTEGER timeout;
    ULONG replyLen = 0;
    KIRQL irql;
    NTSTATUS status;

    if (gClientPort == NULL || DecisionOut == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    RtlZeroMemory(msgBuf, sizeof(msgBuf));
    RtlZeroMemory(&response, sizeof(response));
    hdr->Magic = AISHIELD_MAGIC;
    hdr->Version = AISHIELD_VERSION;
    hdr->Command = AISHIELD_CMD_FILE_QUERY;
    hdr->PayloadLength = sizeof(AISHIELD_FILE_QUERY);

    KeAcquireSpinLock(&gPolicyLock, &irql);
    query->QueryId = ++gPolicyCache.NextQueryId;
    KeReleaseSpinLock(&gPolicyLock, irql);

    query->Pid = Pid;
    query->FolderPolicy = FolderPolicy;
    if (AppName != NULL && AppName->Buffer != NULL) {
        RtlCopyMemory(query->AppName, AppName->Buffer,
            min(AppName->Length, (AISHIELD_MAX_APP_NAME - 1) * sizeof(WCHAR)));
    }
    if (Path != NULL && Path->Buffer != NULL) {
        RtlCopyMemory(query->Path, Path->Buffer,
            min(Path->Length, (AISHIELD_MAX_PATH - 1) * sizeof(WCHAR)));
    }

    timeout.QuadPart = -10LL * 1000 * 1000 * 30;

    status = FltSendMessage(
        gFilterHandle,
        &gClientPort,
        msgBuf,
        sizeof(msgBuf),
        &response,
        &replyLen,
        &timeout
    );

    if (!NT_SUCCESS(status) || replyLen < sizeof(AISHIELD_FILE_RESPONSE)) {
        return status;
    }

    *DecisionOut = response.Decision;
    return STATUS_SUCCESS;
}

static NTSTATUS
AiShieldConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
    }
    gClientPort = ClientPort;
    FltReferenceObject(gClientPort);
    gPolicyCache.ClientConnected = TRUE;
    return STATUS_SUCCESS;
}

static VOID
AiShieldDisconnectNotify(_In_opt_ PVOID ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
    gPolicyCache.ClientConnected = FALSE;
}

static NTSTATUS
AiShieldMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    PAISHIELD_MSG_HEADER inHdr;
    PAISHIELD_MSG_HEADER outHdr;
    PAISHIELD_SYNC_PAYLOAD syncPayload;
    KIRQL irql;

    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    if (InputBuffer == NULL || InputBufferLength < sizeof(AISHIELD_MSG_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    inHdr = (PAISHIELD_MSG_HEADER)InputBuffer;
    if (inHdr->Magic != AISHIELD_MAGIC || inHdr->Version != AISHIELD_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    if (inHdr->Command == AISHIELD_CMD_PING) {
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(AISHIELD_MSG_HEADER)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        outHdr = (PAISHIELD_MSG_HEADER)OutputBuffer;
        RtlZeroMemory(outHdr, sizeof(AISHIELD_MSG_HEADER));
        outHdr->Magic = AISHIELD_MAGIC;
        outHdr->Version = AISHIELD_VERSION;
        outHdr->Command = AISHIELD_CMD_POLICY_ACK;
        if (ReturnOutputBufferLength != NULL) {
            *ReturnOutputBufferLength = sizeof(AISHIELD_MSG_HEADER);
        }
        return STATUS_SUCCESS;
    }

    if (inHdr->Command == AISHIELD_CMD_SYNC_POLICY) {
        if (InputBufferLength < sizeof(AISHIELD_MSG_HEADER) + sizeof(AISHIELD_SYNC_PAYLOAD)) {
            return STATUS_INVALID_PARAMETER;
        }
        syncPayload = (PAISHIELD_SYNC_PAYLOAD)((PUCHAR)InputBuffer + sizeof(AISHIELD_MSG_HEADER));
        KeAcquireSpinLock(&gPolicyLock, &irql);
        RtlCopyMemory(&gPolicyCache.Sync, syncPayload, sizeof(AISHIELD_SYNC_PAYLOAD));
        KeReleaseSpinLock(&gPolicyLock, irql);

        if (OutputBuffer != NULL && OutputBufferLength >= sizeof(AISHIELD_MSG_HEADER)) {
            outHdr = (PAISHIELD_MSG_HEADER)OutputBuffer;
            RtlZeroMemory(outHdr, sizeof(AISHIELD_MSG_HEADER));
            outHdr->Magic = AISHIELD_MAGIC;
            outHdr->Version = AISHIELD_VERSION;
            outHdr->Command = AISHIELD_CMD_POLICY_ACK;
            if (ReturnOutputBufferLength != NULL) {
                *ReturnOutputBufferLength = sizeof(AISHIELD_MSG_HEADER);
            }
        }
        return STATUS_SUCCESS;
    }

    if (inHdr->Command == AISHIELD_CMD_FILE_RESPONSE) {
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
AiShieldPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    PEPROCESS process;
    ULONG pid;
    UNICODE_STRING appName;
    UNICODE_STRING filePath;
    ULONG folderPolicy = AISHIELD_POLICY_ASK;
    ULONG decision = AISHIELD_DECISION_ALLOW;
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!FLT_IS_IRP_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = FltGetRequestorProcessId(Data);
    if (!AiShieldIsAiProcess(pid, &appName)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    filePath = nameInfo->Name;
    if (!AiShieldMatchProtectedPath(&filePath, &folderPolicy)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (folderPolicy == AISHIELD_POLICY_ALLOW) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (folderPolicy == AISHIELD_POLICY_BLOCK) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (gPolicyCache.ClientConnected) {
        status = AiShieldQueryUserMode(&filePath, pid, &appName, folderPolicy, &decision);
        if (NT_SUCCESS(status) && decision == AISHIELD_DECISION_BLOCK) {
            FltReleaseFileNameInformation(nameInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
AiShieldPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(AISHIELD_PORT_NAME);

    UNREFERENCED_PARAMETER(RegistryPath);

    if (!gLockInit) {
        KeInitializeSpinLock(&gPolicyLock);
        gLockInit = TRUE;
    }

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    InitializeObjectAttributes(
        &oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(
        gFilterHandle, &gServerPort, &oa, NULL,
        AiShieldConnectNotify, AiShieldDisconnectNotify,
        AiShieldMessageNotify, 1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    return status;
}

NTSTATUS
AiShieldMinifilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    return STATUS_SUCCESS;
}
