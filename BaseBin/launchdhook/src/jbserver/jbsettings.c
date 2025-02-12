#include "jbsettings.h"
#include <libjailbreak/info.h>

#include <libjailbreak/libjailbreak.h>

int jbsettings_get(const char *key, xpc_object_t *valueOut)
{
	if (!strcmp(key, "markAppsAsDebugged")) {
		*valueOut = xpc_bool_create(jbsetting(markAppsAsDebugged));
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier")) {
		*valueOut = xpc_double_create(jbsetting(jetsamMultiplier));
		return 0;
	}
	else if(strcmp(key, "DevMode")==0) {
		uint64_t developer_mode_storage = kread64(ksymbol(developer_mode_enabled));
		int state = kread8(developer_mode_storage);
		*valueOut = xpc_bool_create(state);
		return 0;
	}
	return -1;
}

int jbsettings_set(const char *key, xpc_object_t value)
{
	if (!strcmp(key, "markAppsAsDebugged") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = xpc_bool_get_value(value);
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier") && xpc_get_type(value) == XPC_TYPE_DOUBLE) {
		gSystemInfo.jailbreakSettings.jetsamMultiplier = xpc_double_get_value(value);
		return 0;
	}
	else if(strcmp(key, "DevMode")==0 && xpc_get_type(value) == XPC_TYPE_BOOL) {
		int state = xpc_bool_get_value(value);
		uint64_t developer_mode_storage = kread64(ksymbol(developer_mode_enabled));
		kwrite8(developer_mode_storage, state);
		return 0;
	}
	return -1;
}