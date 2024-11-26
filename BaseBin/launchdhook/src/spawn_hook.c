#include <spawn.h>
#include "../systemhook/src/common.h"
#include "boomerang.h"
#include "crashreporter.h"
#include "update.h"
#include <libjailbreak/util.h>
#include <substrate.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
extern char **environ;

extern int systemwide_trust_binary(const char *binaryPath, xpc_object_t preferredArchsArray);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);

#define LOG_PROCESS_LAUNCHES 0

extern bool gInEarlyBoot;

void early_boot_done(void)
{
	gInEarlyBoot = false;
}

/*
int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	// we need to disable the crash reporter during the orig call
	// otherwise the child process inherits the exception ports
	// and this would trip jailbreak detections
	crashreporter_pause();	
	int r = __posix_spawn_orig(pid, path, desc, argv, envp);
	crashreporter_resume();

	return r;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	if (path) {
		char executablePath[1024];
		uint32_t bufsize = sizeof(executablePath);
		_NSGetExecutablePath(&executablePath[0], &bufsize);
		if (!strcmp(path, executablePath)) {
			// This spawn will perform a userspace reboot...
			// Instead of the ordinary hook, we want to reinsert this dylib
			// This has already been done in envp so we only need to call the original posix_spawn

			// We are back in "early boot" for the remainder of this launchd instance
			// Mainly so we don't lock up while spawning boomerang
			gInEarlyBoot = true;

#if LOG_PROCESS_LAUNCHES
			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
			fprintf(f, "==== USERSPACE REBOOT ====\n");
			fclose(f);
#endif

			// Before the userspace reboot, we want to stash the primitives into boomerang
			boomerang_stashPrimitives();

			// Fix Xcode debugging being broken after the userspace reboot
			unmount("/Developer", MNT_FORCE);

			// If there is a pending jailbreak update, apply it now
			const char *stagedJailbreakUpdate = getenv("STAGED_JAILBREAK_UPDATE");
			if (stagedJailbreakUpdate) {
				int r = jbupdate_basebin(stagedJailbreakUpdate);
				unsetenv("STAGED_JAILBREAK_UPDATE");
			}

			// Always use environ instead of envp, as boomerang_stashPrimitives calls setenv
			// setenv / unsetenv can sometimes cause environ to get reallocated
			// In that case envp may point to garbage or be empty
			// Say goodbye to this process
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, environ);
		}
	}

#if LOG_PROCESS_LAUNCHES
	if (path) {
		FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		fprintf(f, "%s", path);
		int ai = 0;
		while (argv) {
			if (argv[ai]) {
				if (ai >= 1) {
					fprintf(f, " %s", argv[ai]);
				}
				ai++;
			}
			else {
				break;
			}
		}
		fprintf(f, "\n");
		fclose(f);

		// if (!strcmp(path, "/usr/libexec/xpcproxy")) {
		// 	const char *tmpBlacklist[] = {
		// 		"com.apple.logd"
		// 	};
		// 	size_t blacklistCount = sizeof(tmpBlacklist) / sizeof(tmpBlacklist[0]);
		// 	for (size_t i = 0; i < blacklistCount; i++)
		// 	{
		// 		if (!strcmp(tmpBlacklist[i], firstArg)) {
		// 			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		// 			fprintf(f, "blocked injection %s\n", firstArg);
		// 			fclose(f);
		// 			return __posix_spawn_orig_wrapper(pid, path, file_actions, desc, envp);
		// 		}
		// 	}
		// }
	}
#endif

	// We can't support injection into processes that get spawned before the launchd XPC server is up
	// (Technically we could but there is little reason to, since it requires additional work)
	if (gInEarlyBoot) {
		if (!strcmp(path, "/usr/libexec/xpcproxy")) {
			// The spawned process being xpcproxy indicates that the launchd XPC server is up
			// All processes spawned including this one should be injected into
			early_boot_done();
		}
		else {
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
		}
	}

	return posix_spawn_hook_shared(pid, path, desc, argv, envp, __posix_spawn_orig_wrapper, systemwide_trust_binary, platform_set_process_debugged, jbsetting(jetsamMultiplier));
}
*/


#include <libjailbreak/kernel.h>
#include <libjailbreak/deny.h>
#include <libjailbreak/log.h>
#import "../systemhook/src/envbuf.h"

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700

int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *__restrict, int *__restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

int __posix_spawn_orig_wrapper(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
    short flags = 0;
    if (desc && desc->attrp) {
        posix_spawnattr_t attr = desc->attrp;
        posix_spawnattr_getflags(&attr, &flags);
    }
    JBLogDebug("launchd spawn path=%s flags=%x", path, flags);
    if (argv) for (int i = 0; argv[i]; i++) JBLogDebug("\targs[%d] = %s", i, argv[i]);
    if (envp) for (int i = 0; envp[i]; i++) JBLogDebug("\tenvp[%d] = %s", i, envp[i]);

    int pid = 0;
    if (!pidp) pidp = &pid;

    // we need to disable the crash reporter during the orig call
    // otherwise the child process inherits the exception ports
    // and this would trip jailbreak detections
    crashreporter_pause();
    int r = __posix_spawn_orig(pidp, path, desc, argv, envp);
    crashreporter_resume();

    pid = *pidp;

    JBLogDebug("spawn ret=%d pid=%d", r, pid);

    return r;
}

int __posix_spawn_hook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}
	posix_spawnattr_t attrp = &desc->attrp;

	if (path) {
		char executablePath[1024];
		uint32_t bufsize = sizeof(executablePath);
		_NSGetExecutablePath(&executablePath[0], &bufsize);
		if (!strcmp(path, executablePath)) {
			// This spawn will perform a userspace reboot...
			// Instead of the ordinary hook, we want to reinsert this dylib
			// This has already been done in envp so we only need to call the original posix_spawn

			// We are back in "early boot" for the remainder of this launchd instance
			// Mainly so we don't lock up while spawning boomerang
			gInEarlyBoot = true;

#if LOG_PROCESS_LAUNCHES
			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
			fprintf(f, "==== USERSPACE REBOOT ====\n");
			fclose(f);
#endif

			// Before the userspace reboot, we want to stash the primitives into boomerang
			boomerang_stashPrimitives();

			// Fix Xcode debugging being broken after the userspace reboot
			unmount("/Developer", MNT_FORCE);

			// If there is a pending jailbreak update, apply it now
			const char *stagedJailbreakUpdate = getenv("STAGED_JAILBREAK_UPDATE");
			if (stagedJailbreakUpdate) {
				int r = jbupdate_basebin(stagedJailbreakUpdate);
				unsetenv("STAGED_JAILBREAK_UPDATE");
			}

            // Suspend launchd and patch GET_TASK_ALLOW in boomerang
            short flags = 0;
            posix_spawnattr_getflags(attrp, &flags);
            posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);

			// Always use environ instead of envp, as boomerang_stashPrimitives calls setenv
			// setenv / unsetenv can sometimes cause environ to get reallocated
			// In that case envp may point to garbage or be empty
			// Say goodbye to this process
			return __posix_spawn_orig_wrapper(pidp, path, desc, argv, environ);
		}
	}

	// We can't support injection into processes that get spawned before the launchd XPC server is up
	// (Technically we could but there is little reason to, since it requires additional work)
	if (gInEarlyBoot) {
		if (!strcmp(path, "/usr/libexec/xpcproxy")) {
			// The spawned process being xpcproxy indicates that the launchd XPC server is up
			// All processes spawned including this one should be injected into
			early_boot_done();
		}
		else {
			return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
		}
	}

    if (isBlacklisted(path)) {
        JBLogDebug("blacklisted app %s", path);

		char **envc = envbuf_mutcopy((const char **)envp);

		//choicy may set these 
		envbuf_unsetenv(&envc, "_SafeMode");
		envbuf_unsetenv(&envc, "_MSSafeMode");

        int ret = __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);

		envbuf_free(envc);

        return ret;
    }

    short flags = 0;
    posix_spawnattr_getflags(attrp, &flags);

    int proctype = 0;
    posix_spawnattr_getprocesstype_np(attrp, &proctype);

    bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
    bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;
	bool set_debugged = (flags & POSIX_SPAWN_START_SUSPENDED) != 0;

    if (should_suspend) {
        posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
    }

	// on some devices dyldhook may fail due to vm_protect(VM_PROT_READ|VM_PROT_WRITE), 2, (os/kern) protection failure in dsc::__DATA_CONST:__const, 
	// so we need to disable dyld-in-cache here. (or we can use VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
	char **envc = envbuf_mutcopy((const char **)envp);
	envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");

    int pid = 0;
    if (!pidp) pidp = &pid;
    int ret = posix_spawn_hook_shared(pidp, path, desc, argv, envc, __posix_spawn_orig_wrapper, systemwide_trust_binary, platform_set_process_debugged, jbsetting(jetsamMultiplier));
    pid = *pidp;

	envbuf_free(envc);
	
	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

    if (ret != 0){
        JBLogDebug("spawn error ret=%d errno=%d err=%s", ret, errno, strerror(errno));
    }

    if (ret == 0 && pid > 0) {
		if(set_debugged) {
			platform_set_process_debugged(pid, false);
		}
		if(should_suspend) {
			// give get-task-allow entitlement to make dyld respect DYLD_INSERT_LIBRARIES
			proc_csflags_patch(pid);
		}
        if (should_resume) {
            kill(pid, SIGCONT);
        }
    }

    return ret;
}

void initSpawnHooks(void)
{
	MSHookFunction(&__posix_spawn, (void *)__posix_spawn_hook, NULL);
}