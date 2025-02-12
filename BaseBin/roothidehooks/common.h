
#include <stdbool.h>


bool isJailbreakPath(const char* path);

bool isNormalAppPath(const char* path);

bool isSandboxedApp(pid_t pid, const char* path);

int proc_pidpath(int pid, void * buffer, uint32_t  buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
