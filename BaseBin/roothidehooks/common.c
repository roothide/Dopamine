#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include "common.h"

enum sandbox_filter_type { SANDBOX_FILTER_NONE };
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_REPORT;
extern int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

char* getAppUUIDOffset(const char* path)
{
    if(!path) return NULL;

    char rp[PATH_MAX];
    if(!realpath(path, rp)) return NULL;

    if(strncmp(rp, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NULL;

    char* p1 = rp + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NULL;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NULL;
	
	*p2 = '\0';

	return strdup(rp);
}

bool hasTrollstoreMarker(const char* uuidpath)
{
	char* p1=NULL;
	asprintf(&p1, "%s/_TrollStore", uuidpath);

	int trollapp = access(p1, F_OK);
	if(trollapp != 0) 
	{
		free((void*)p1);
		asprintf(&p1, "%s/_TrollStoreLite", uuidpath);
		trollapp = access(p1, F_OK);
	}

	free((void*)p1);

	if(trollapp==0) 
		return true;

	return false;
}

bool isJailbreakPath(const char* path)
{
    if(!path) return false;

	struct statfs fs;
	if(statfs(path, &fs)==0)
	{
		if(strcmp(fs.f_mntonname, "/private/var") != 0)
			return false;
	}

	char* p1 = getAppUUIDOffset(path);
	if(!p1) return true; //reject by default

	bool trollapp = hasTrollstoreMarker(p1);

	free((void*)p1);

	if(trollapp) 
		return true;

    return false;
}

bool isNormalAppPath(const char* path)
{
    if(!path) return false;
    
	char* p1 = getAppUUIDOffset(path);
	if(!p1) return false; //allow by default

	bool trollapp = hasTrollstoreMarker(p1);

	free((void*)p1);

	if(trollapp) return false;

    return true;
}

bool isSandboxedApp(pid_t pid, const char* path)
{
    if(!path) return false;
    
	char* p1 = getAppUUIDOffset(path);
	if(!p1) return false;

	free((void*)p1);

	bool sandboxed = sandbox_check(pid, "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) != 0;

	return sandboxed;
}