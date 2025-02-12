#include <CoreFoundation/CoreFoundation.h>
#include <spawn.h>
#include <xpc/xpc.h>
#include "private.h"

// #define HOOK_DYLIB_PATH "/usr/lib/systemhook.dylib"
extern char HOOK_DYLIB_PATH[];

#include <stdlib.h>
#include <sys/syslog.h>
#include <os/log.h>
#define SYSLOG(...) do {openlog("systemhook",LOG_PID,LOG_AUTH);syslog(LOG_DEBUG, __VA_ARGS__);closelog();} while(0)

int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

typedef enum 
{
	kSpawnConfigInject = 1 << 0,
	kSpawnConfigTrust = 1 << 1,
} kSpawnConfig;

int __posix_spawn(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);
int __execve(const char *path, char *const argv[], char *const envp[]);

bool string_has_prefix(const char *str, const char* prefix);
bool string_has_suffix(const char* str, const char* suffix);

int __posix_spawn_orig(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char * const envp[restrict]);
int __execve_orig(const char *path, char *const argv[], char *const envp[]);

int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path));
int posix_spawn_hook_shared(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict], void *orig, int (*trust_binary)(const char *path, xpc_object_t preferredArchsArray), int (*set_process_debugged)(uint64_t pid, bool fullyDebugged), double jetsamMultiplier);
int execve_hook_shared(const char *path, char *const argv[], char *const envp[], void *orig, int (*trust_binary)(const char *path, xpc_object_t preferredArchsArray));