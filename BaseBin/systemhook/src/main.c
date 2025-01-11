#include "common.h"

#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <paths.h>
#include <util.h>
#include <ptrauth.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/codesign.h>
#include <libjailbreak/jbroot.h>
#include "litehook.h"
#include "sandbox.h"
#include "private.h"

bool gFullyDebugged = false;
static void *gLibSandboxHandle;
char *JB_BootUUID = NULL;
char *JB_RootPath = NULL;
char *get_jbroot(void) { return JB_RootPath; }

static char gExecutablePath[PATH_MAX];
static int load_executable_path(void)
{
	char executablePath[PATH_MAX];
	uint32_t bufsize = PATH_MAX;
	if (_NSGetExecutablePath(executablePath, &bufsize) == 0) {
		if (realpath(executablePath, gExecutablePath) != NULL) return 0;
	}
	return -1;
}

static char *JB_SandboxExtensions = NULL;
void apply_sandbox_extensions(void)
{
	if (JB_SandboxExtensions) {
		char *JB_SandboxExtensions_dup = strdup(JB_SandboxExtensions);
		char *extension = strtok(JB_SandboxExtensions_dup, "|");
		while (extension != NULL) {
			sandbox_extension_consume(extension);
			extension = strtok(NULL, "|");
		}
		free(JB_SandboxExtensions_dup);
	}
}

void *(*sandbox_apply_orig)(void *) = NULL;
void *sandbox_apply_hook(void *a1)
{
	void *r = sandbox_apply_orig(a1);
	apply_sandbox_extensions();
	return r;
}

int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;

	uint64_t dyldPacDiversifier = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **dyldFuncPtrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, dyldPacDiversifier);
	if (!dyldFuncPtrs) return -1;

	if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		uint64_t location = (uint64_t)&dyldFuncPtrs[idx];
		uint64_t pacDiversifier = (location & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);

		*orig = ptrauth_auth_and_resign(dyldFuncPtrs[idx], ptrauth_key_process_independent_code, pacDiversifier, ptrauth_key_function_pointer, 0);
		dyldFuncPtrs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, pacDiversifier);
		vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ);
		return 0;
	}

	return -1;
}

// All dlopen/dlsym calls use __builtin_return_address(0) to determine what library called it
// Since we hook them, if we just call the original function on our own, the return address will always point to systemhook
// Therefore we must ensure the call to the original function is a tail call, 
// which ensures that the stack and lr are restored and the compiler turns the call into a direct branch
// This is done via __attribute__((musttail)), this way __builtin_return_address(0) will point to the original calling library instead of systemhook

void* (*dyld_dlopen_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_hook(void *dyld, const char* path, int mode)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library(path, __builtin_return_address(0));
	}
    __attribute__((musttail)) return dyld_dlopen_orig(dyld, path, mode);
}

void* (*dyld_dlopen_from_orig)(void *dyld, const char* path, int mode, void* addressInCaller);
void* dyld_dlopen_from_hook(void *dyld, const char* path, int mode, void* addressInCaller)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library(path, addressInCaller);
	}
	__attribute__((musttail)) return dyld_dlopen_from_orig(dyld, path, mode, addressInCaller);
}

void* (*dyld_dlopen_audited_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_audited_hook(void *dyld, const char* path, int mode)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_audited_orig(dyld, path, mode);
}

bool (*dyld_dlopen_preflight_orig)(void *dyld, const char *path);
bool dyld_dlopen_preflight_hook(void *dyld, const char* path)
{
	if (path) {
		jbclient_trust_library(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_preflight_orig(dyld, path);
}

void *(*dyld_dlsym_orig)(void *dyld, void *handle, const char *name);
void *dyld_dlsym_hook(void *dyld, void *handle, const char *name)
{
	if (handle == gLibSandboxHandle && !strcmp(name, "sandbox_apply")) {
		// We abuse the fact that libsystem_sandbox will call dlsym to get the sandbox_apply pointer here
		// Because we can just return a different pointer, we avoid doing instruction replacements
		return sandbox_apply_hook;
	}
	__attribute__((musttail)) return dyld_dlsym_orig(dyld, handle, name);
}

int ptrace_hook(int request, pid_t pid, caddr_t addr, int data)
{
	int r = syscall(SYS_ptrace, request, pid, addr, data);

	// ptrace works on any process when the caller is unsandboxed,
	// but when the victim process does not have the get-task-allow entitlement,
	// it will fail to set the debug flags, therefore we patch ptrace to manually apply them
	// processes that have tweak injection enabled will have their debug flags already set
	// this is only relevant for ones that don't, e.g. if you disable tweak injection on an app via choicy
	// but still want to be able to attach a debugger to them
	if (r == 0 && (request == PT_ATTACHEXC || request == PT_ATTACH)) {
		jbclient_platform_set_process_debugged(pid, true);
		jbclient_platform_set_process_debugged(getpid(), true);
	}

	return r;
}

#ifndef __arm64e__

// The NECP subsystem is the only thing in the kernel that ever checks CS_VALID on userspace processes (Only on iOS >=16)
// In order to not break system functionality, we need to readd CS_VALID before any of these are invoked

int necp_match_policy_hook(uint8_t *parameters, size_t parameters_size, void *returned_result)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_match_policy, parameters, parameters_size, returned_result);
}

int necp_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_open, flags);
}

int necp_client_action_hook(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_client_action, necp_fd, action, client_id, client_id_len, buffer, buffer_size);
}

int necp_session_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_open, flags);
}

int necp_session_action_hook(int necp_fd, uint32_t action, uint8_t *in_buffer, size_t in_buffer_length, uint8_t *out_buffer, size_t out_buffer_length)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_action, necp_fd, action, in_buffer, in_buffer_length, out_buffer, out_buffer_length);
}

// For the userland, there are multiple processes that will check CS_VALID for one reason or another
// As we inject system wide (or at least almost system wide), we can just patch the source of the info though - csops itself
// Additionally we also remove CS_DEBUGGED while we're at it, as on arm64e this also is not set and everything is fine
// That way we have unified behaviour between both arm64 and arm64e

int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
			if (pid == getpid() && gFullyDebugged) {
				*csflag |= CS_DEBUGGED;
			}
		}
	}
	return rv;
}

int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token)
{
	int rv = syscall(SYS_csops_audittoken, pid, ops, useraddr, usersize, token);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
			if (pid == getpid() && gFullyDebugged) {
				*csflag |= CS_DEBUGGED;
			}
		}
	}
	return rv;
}

#endif

bool should_enable_tweaks(void)
{
	if (access(JBROOT_PATH("/basebin/.safe_mode"), F_OK) == 0) {
		return false;
	}

	char *tweaksDisabledEnv = getenv("DISABLE_TWEAKS");
	if (tweaksDisabledEnv) {
		if (!strcmp(tweaksDisabledEnv, "1")) {
			return false;
		}
	}

	const char *safeModeValue = getenv("_SafeMode");
	const char *msSafeModeValue = getenv("_MSSafeMode");
	if (safeModeValue) {
		if (!strcmp(safeModeValue, "1")) {
			return false;
		}
	}
	if (msSafeModeValue) {
		if (!strcmp(msSafeModeValue, "1")) {
			return false;
		}
	}

	const char *tweaksDisabledPathSuffixes[] = {
		// System binaries
		"/usr/libexec/xpcproxy",

		// Dopamine app itself (jailbreak detection bypass tweaks can break it)
		"Dopamine.app/Dopamine",
	};
	for (size_t i = 0; i < sizeof(tweaksDisabledPathSuffixes) / sizeof(const char*); i++) {
		if (string_has_suffix(gExecutablePath, tweaksDisabledPathSuffixes[i])) return false;
	}

	if (__builtin_available(iOS 16.0, *)) {
		// These seem to be problematic on iOS 16+ (dyld gets stuck in a weird way when opening TweakLoader)
		const char *iOS16TweaksDisabledPaths[] = {
			"/usr/libexec/logd",
			"/usr/sbin/notifyd",
			"/usr/libexec/usermanagerd",
		};
		for (size_t i = 0; i < sizeof(iOS16TweaksDisabledPaths) / sizeof(const char*); i++) {
			if (!strcmp(gExecutablePath, iOS16TweaksDisabledPaths[i])) return false;
		}
	}

	return true;
}


#include "envbuf.h"

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

int posix_spawn_hook_roothide(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, 
								char *const argv[restrict], char *const envp[restrict], void *orig, 
								int (*trust_binary)(const char *path, xpc_object_t preferredArchsArray), 
								int (*set_process_debugged)(uint64_t pid, bool fullyDebugged), 
								double jetsamMultiplier)
{
	if(!path) { //Don't crash here due to bad posix_spawn call
		return posix_spawn_hook_shared(pidp, path, desc, argv, envp, orig, trust_binary, set_process_debugged, jetsamMultiplier);
	}

	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;
	bool set_debugged = (flags & POSIX_SPAWN_START_SUSPENDED) != 0;
	bool patch_exec = should_suspend && (flags & POSIX_SPAWN_SETEXEC) != 0;

	if (should_suspend) {
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	}

	if (patch_exec) {
		if (jbclient_patch_exec_add(path, should_resume) != 0) { // jdb fault?
			//restore flags
			posix_spawnattr_setflags(attrp, flags);
			return 199;
		}
	}

	// on some devices dyldhook may fail due to vm_protect(VM_PROT_READ|VM_PROT_WRITE), 2, (os/kern) protection failure in dsc::__DATA_CONST:__const, 
	// so we need to disable dyld-in-cache here. (or we can use VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
	char **envc = envbuf_mutcopy((const char **)envp);
	envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");

	int pid = 0;
	int ret = posix_spawn_hook_shared(&pid, path, desc, argv, envc, orig, trust_binary, set_process_debugged, jetsamMultiplier);
	if (pidp) *pidp = pid;

	envbuf_free(envc);

	// maybe caller will use it again? restore flags
	posix_spawnattr_setflags(attrp, flags);

	if (patch_exec) { //exec failed?
		jbclient_patch_exec_del(path);
	} else if (ret == 0 && pid > 0) {
		if(set_debugged) {
			set_process_debugged(pid, false);
		}
		if (should_suspend) {
			if(jbclient_patch_spawn(pid, should_resume) != 0) { // jdb fault? kill
				kill(pid, SIGKILL);
				return 198;
			}
		}
	}

	return ret;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char * const envp[restrict])
{
	return posix_spawn_hook_roothide(pid, path, desc, argv, envp, (void *)__posix_spawn_orig, jbclient_trust_binary, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
}

int __posix_spawn_hook_with_filter(pid_t *restrict pid, const char *restrict path, char *const argv[restrict], char * const envp[restrict], struct _posix_spawn_args_desc *desc, int *ret)
{
	*ret = posix_spawn_hook_roothide(pid, path, desc, argv, envp, (void *)__posix_spawn_orig, jbclient_trust_binary, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
	return 1;
}

#include <sys/mount.h>
int __execve_hook(const char *path, char *const argv[], char *const envp[])
{
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int ret = posix_spawn(NULL, path, NULL, &attr, argv, envp);
	posix_spawnattr_destroy(&attr);

	if(ret==EPERM && access(path, X_OK)==0)
	{
		struct statfs fs1;
		bool isPlatformBinary1 = statfs(gExecutablePath, &fs1)==0 && strcmp(fs1.f_mntonname, "/private/var") != 0;

		struct statfs fs2;
		bool isPlatformBinary2 = statfs(path, &fs2)==0 && strcmp(fs2.f_mntonname, "/private/var") != 0;
		
		if(isPlatformBinary1 && isPlatformBinary2) {
			return execve_hook_shared(path, argv, envp, (void *)__execve_orig, jbclient_trust_binary);
		}
	}

	if(ret != 0) {
		// posix_spawn will return errno and restore errno if it fails
		// so we need to set errno by ourself
		errno = ret; 
		ret = -1;
	}

	return ret;
}


#include <pwd.h>
#include <libgen.h>
#include <stdio.h>
#include <libproc.h>
#include <libproc_private.h>
#include <sys/sysctl.h>

//some process may be killed by sandbox if call systme getppid()
pid_t __getppid()
{
    struct proc_bsdinfo procInfo;
	if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) <= 0) {
		return -1;
	}
    return procInfo.pbi_ppid;
}

static uid_t _CFGetSVUID(bool *successful) {
    uid_t uid = -1;
    struct kinfo_proc kinfo;
    u_int miblen = 4;
    size_t  len;
    int mib[miblen];
    int ret;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    len = sizeof(struct kinfo_proc);
    ret = sysctl(mib, miblen, &kinfo, &len, NULL, 0);
    if (ret != 0) {
        uid = -1;
        *successful = false;
    } else {
        uid = kinfo.kp_eproc.e_pcred.p_svuid;
        *successful = true;
    }
    return uid;
}

bool _CFCanChangeEUIDs(void) {
    static bool canChangeEUIDs;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uid_t euid = geteuid();
        uid_t uid = getuid();
        bool gotSVUID = false;
        uid_t svuid = _CFGetSVUID(&gotSVUID);
        canChangeEUIDs = (uid == 0 || uid != euid || svuid != euid || !gotSVUID);
    });
    return canChangeEUIDs;
}

void loadPathHook()
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		void* roothidehooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		void (*pathhook)() = dlsym(roothidehooks, "pathhook");
		pathhook();
	});
}

void redirect_path_env(const char* rootdir)
{
    //for now libSystem should be initlized, container should be set.

    char* homedir = NULL;

/* 
there is a bug in NSHomeDirectory,
if a containerized root process changes its uid/gid, 
NSHomeDirectory will return a home directory that it cannot access. (exclude NSTemporaryDirectory)
We just keep this bug:
*/
    if(!issetugid()) // issetugid() should always be false at this time. (but how about persona-mgmt? idk)
    {
        homedir = getenv("CFFIXED_USER_HOME");
        if(homedir)
        {
#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" // +/Application,PluginKitPlugin,InternalDaemon
            if(strncmp(homedir, CONTAINER_PATH_PREFIX, sizeof(CONTAINER_PATH_PREFIX)-1) == 0)
            {
                return; //containerized
            }
            else
            {
                homedir = NULL; //from parent, drop it
            }
        }
    }

    if(!homedir) {
        struct passwd* pwd = getpwuid(geteuid());
        if(pwd && pwd->pw_dir) {
            homedir = pwd->pw_dir;
        }
    }

    // if(!homedir) {
    //     //CFCopyHomeDirectoryURL does, but not for NSHomeDirectory
    //     homedir = getenv("HOME");
    // }

    if(!homedir) {
        homedir = "/var/empty";
    }

    char newhome[PATH_MAX]={0};
    snprintf(newhome,sizeof(newhome),"%s/%s",rootdir,homedir);
    setenv("CFFIXED_USER_HOME", newhome, 1);
}

void redirect_paths(const char* rootdir)
{
    do {
        
        char executablePath[PATH_MAX]={0};
        uint32_t bufsize=sizeof(executablePath);
        if(_NSGetExecutablePath(executablePath, &bufsize) != 0)
            break;
        
        char realexepath[PATH_MAX];
        if(!realpath(executablePath, realexepath))
            break;
            
        char realjbroot[PATH_MAX];
        if(!realpath(rootdir, realjbroot))
            break;
        
        if(realjbroot[strlen(realjbroot)] != '/')
            strcat(realjbroot, "/");
        
        if(strncmp(realexepath, realjbroot, strlen(realjbroot)) != 0)
            break;

        //for jailbroken binaries
        redirect_path_env(rootdir);
		
		if(_CFCanChangeEUIDs()) {
			loadPathHook();
		}
    
        pid_t ppid = __getppid();
        assert(ppid > 0);
        if(ppid != 1)
            break;
        
        char pwd[PATH_MAX];
        if(getcwd(pwd, sizeof(pwd)) == NULL)
            break;
        if(strcmp(pwd, "/") != 0)
            break;
    
        assert(chdir(rootdir)==0);
        
    } while(0);
}

//export for PatchLoader
__attribute__((visibility("default"))) int PLRequiredJIT() {
	return 0;
}

char HOOK_DYLIB_PATH[PATH_MAX] = {0};

__attribute__((constructor)) static void initializer(void)
{
//////////////////////////////////////////////
	struct dl_info di={0};
	dladdr((void*)initializer, &di);
	strncpy(HOOK_DYLIB_PATH, di.dli_fname, sizeof(HOOK_DYLIB_PATH));
/////////////////////////////////////////////////////////////////////////

	// Tell jbserver (in launchd) that this process exists
	// This will disable page validation, which allows the rest of this constructor to apply hooks
	if (jbclient_process_checkin(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) != 0) return;

	// Apply sandbox extensions
	apply_sandbox_extensions();

	// Unset DYLD_INSERT_LIBRARIES, but only if systemhook itself is the only thing contained in it
	// Feeable attempt at making jailbreak detection harder
	const char *dyldInsertLibraries = getenv("DYLD_INSERT_LIBRARIES");
	if (dyldInsertLibraries) {
		if (!strcmp(dyldInsertLibraries, HOOK_DYLIB_PATH)) {
			unsetenv("DYLD_INSERT_LIBRARIES");
		}
	}

	// Apply posix_spawn / execve hooks
	if (__builtin_available(iOS 16.0, *)) {
		litehook_hook_function(__posix_spawn, __posix_spawn_hook);
		litehook_hook_function(__execve, __execve_hook);
	}
	else {
		// On iOS 15 there is a way to hook posix_spawn and execve without doing instruction replacements
		// This is fairly convinient due to instruction replacements being presumed to be the primary trigger for spinlock panics on iOS 15 arm64e
		// Unfortunately Apple decided to remove these in iOS 16 :( Doesn't matter too much though because spinlock panics are fixed there

		void **posix_spawn_with_filter = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_posix_spawn_with_filter");
		*posix_spawn_with_filter = __posix_spawn_hook_with_filter;

		void **execve_with_filter = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_execve_with_filter");
		*execve_with_filter = __execve_hook;
	}

	// Initialize stuff neccessary for sandbox_apply hook
	gLibSandboxHandle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_FIRST | RTLD_LOCAL | RTLD_LAZY);
	sandbox_apply_orig = dlsym(gLibSandboxHandle, "sandbox_apply");

	// Apply dyld hooks
	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	if (gDyldPtr) {
		dyld_hook_routine(*gDyldPtr, 14, (void *)&dyld_dlopen_hook, (void **)&dyld_dlopen_orig, 0xBF31);
		dyld_hook_routine(*gDyldPtr, 17, (void *)&dyld_dlsym_hook, (void **)&dyld_dlsym_orig, 0x839D);
		dyld_hook_routine(*gDyldPtr, 18, (void *)&dyld_dlopen_preflight_hook, (void **)&dyld_dlopen_preflight_orig, 0xB1B6);
		dyld_hook_routine(*gDyldPtr, 97, (void *)&dyld_dlopen_from_hook, (void **)&dyld_dlopen_from_orig, 0xD48C);
		dyld_hook_routine(*gDyldPtr, 98, (void *)&dyld_dlopen_audited_hook, (void **)&dyld_dlopen_audited_orig, 0xD2A5);
	}

//////////////////////////////////////////////////////////////////////
  /* after unsandboxing jbroot and applying dyldhooks */

	const char* DYLD_IN_CACHE = getenv("DYLD_IN_CACHE");
	if(strcmp(DYLD_IN_CACHE, "0") == 0) {
		unsetenv("DYLD_IN_CACHE");
	}

	redirect_paths(JB_RootPath);

	dlopen(JBROOT_PATH("/usr/lib/roothideinit.dylib"), RTLD_NOW);
	
//////////////////////////////////////////////////////////////////////////

#ifdef __arm64e__
	// Since pages have been modified in this process, we need to load forkfix to ensure forking will work
	// Optimization: If the process cannot fork at all due to sandbox, we don't need to do anything
	if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0) {
		dlopen(JBROOT_PATH("/basebin/forkfix.dylib"), RTLD_NOW);
	}
#endif

	if (load_executable_path() == 0) {
		// Load rootlesshooks and watchdoghook if neccessary
		if (!strcmp(gExecutablePath, "/usr/sbin/cfprefsd") ||
			!strcmp(gExecutablePath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ||
			!strcmp(gExecutablePath, "/usr/libexec/lsd")) {
			dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		}
		else if (!strcmp(gExecutablePath, "/usr/libexec/watchdogd")) {
			dlopen(JBROOT_PATH("/basebin/watchdoghook.dylib"), RTLD_NOW);
		}

		// ptrace hook to allow attaching a debugger to processes that systemhook did not inject into
		// e.g. allows attaching debugserver to an app where tweak injection has been disabled via choicy
		// since we want to keep hooks minimal and debugserver is the only thing I can think of that would
		// call ptrace and expect it to allow invalid pages, we only hook it in debugserver
		// this check is a bit shit since we rely on the name of the binary, but who cares ¯\_(ツ)_/¯
		if (string_has_suffix(gExecutablePath, "/debugserver")) {
			litehook_hook_function(ptrace, ptrace_hook);
		}

#ifndef __arm64e__
		// On arm64, writing to executable pages removes CS_VALID from the csflags of the process
		// These hooks are neccessary to get the system to behave with this
		// They are ugly but needed
		litehook_hook_function(csops, csops_hook);
		litehook_hook_function(csops_audittoken, csops_audittoken_hook);
		if (__builtin_available(iOS 16.0, *)) {
			litehook_hook_function(necp_match_policy, necp_match_policy_hook);
			litehook_hook_function(necp_open, necp_open_hook);
			litehook_hook_function(necp_client_action, necp_client_action_hook);
			litehook_hook_function(necp_session_open, necp_session_open_hook);
			litehook_hook_function(necp_session_action, necp_session_action_hook);
		}
#endif
		if (__builtin_available(iOS 16.0, *)) {
			bool is_app_path(const char* path);
			if(!is_app_path(gExecutablePath)) {
				litehook_hook_function(__sysctl, __sysctl_hook);
				litehook_hook_function(__sysctlbyname, __sysctlbyname_hook);
			}
		}

		if(string_has_suffix(gExecutablePath, "/Dopamine.app/Dopamine")) {
			loadPathHook();
		}

		dlopen(JBROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW); //require jit

		// Load tweaks if desired
		// We can hardcode /var/jb here since if it doesn't exist, loading TweakLoader.dylib is not going to work anyways
		if (should_enable_tweaks()) {
			const char *tweakLoaderPath = JBROOT_PATH("/usr/lib/TweakLoader.dylib");
			if(access(tweakLoaderPath, F_OK) == 0) {
				void *tweakLoaderHandle = dlopen(tweakLoaderPath, RTLD_NOW);
				if (tweakLoaderHandle != NULL) {
					dlclose(tweakLoaderHandle);
				}
			}
		}

#ifndef __arm64e__
		// Feeable attempt at adding back CS_VALID
		jbclient_cs_revalidate();
#endif
	}
}