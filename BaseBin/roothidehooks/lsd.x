#import <Foundation/Foundation.h>
#import <spawn.h>
#include <roothide.h>
#include "common.h"

extern char **environ;

#pragma GCC diagnostic ignored "-Wobjc-method-access"
#pragma GCC diagnostic ignored "-Wunused-variable"

#define PROC_PIDPATHINFO_MAXSIZE        (4*MAXPATHLEN)
/*lsd can only get path for normal app via proc_pidpath, or we can use
  xpc_connection_get_audit_token([xpc _xpcConnection], &token) //_LSCopyExecutableURLForXPCConnection
  proc_pidpath_audittoken(tokenarg, buffer, size) //_LSCopyExecutableURLForAuditToken 
  */

%hook _LSCanOpenURLManager

- (BOOL)canOpenURL:(NSURL*)url publicSchemes:(BOOL)ispublic privateSchemes:(BOOL)isprivate XPCConnection:(NSXPCConnection*)xpc error:(NSError*)err
{
	BOOL result = %orig;

	if(!result) return result;
	if(!xpc) return result;

	char pathbuf[PROC_PIDPATHINFO_MAXSIZE]={0};
	if(proc_pidpath(xpc.processIdentifier, pathbuf, sizeof(pathbuf)) <= 0) {
		NSLog(@"canOpenURL: unable to get proc path for %d", xpc.processIdentifier);
		return result;
	}

	NSLog(@"canOpenURL:%@ publicSchemes:%d privateSchemes:%d XPCConnection:%@ proc:%d,%s", url, ispublic, isprivate, xpc, xpc.processIdentifier, pathbuf);
	//if(xpc) NSLog(@"canOpenURL:xpc=%@", xpc);

	NSArray* jbschemes = @[
		@"filza", 
		@"db-lmvo0l08204d0a0",
		@"boxsdk-810yk37nbrpwaee5907xc4iz8c1ay3my",
		@"com.googleusercontent.apps.802910049260-0hf6uv6nsj21itl94v66tphcqnfl172r",
		@"sileo",
		@"zbra", 
		@"santander", 
		@"icleaner", 
		@"xina", 
		@"ssh",
		@"apt-repo", 
		@"cydia",
		@"activator",
		@"postbox",
	];

	if(isSandboxedApp(xpc.processIdentifier, pathbuf))
	{
		if([jbschemes containsObject:url.scheme.lowercaseString]) {
			NSLog(@"block %@ for %s", url, pathbuf);
			return NO;
		}
	}

	return result;
}

%end


%hook _LSQueryContext

-(NSMutableDictionary*)_resolveQueries:(NSMutableSet*)queries XPCConnection:(NSXPCConnection*)xpc error:(NSError*)err 
{
	NSMutableDictionary* result = %orig;
	/*
	result: @{
		queries[0]: @[data1, data2, ...],
		queries[1]: @[data1, data2, ...],
	}
	*/

	if(!result) return result;
	if(!xpc) return result;
	
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE]={0};
	if(proc_pidpath(xpc.processIdentifier, pathbuf, sizeof(pathbuf)) <= 0) {
		NSLog(@"_resolveQueries: unable to get proc path for %d", xpc.processIdentifier);
		return result;
	}

	if(!isNormalAppPath(pathbuf)) return result;

	NSLog(@"_resolveQueries:%@:%@ XPCConnection:%@ result=%@/%ld proc:%d,%s", [queries class], queries, xpc, result.class, result.count, xpc.processIdentifier, pathbuf);
	//NSLog(@"result=%@, %@", result.allKeys, result.allValues);
	for(id key in result)
	{
		NSLog(@"key type: %@, value type: %@", [key class], [result[key] class]);
		if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")]
			|| [key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithIdentifier")]
			|| [key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithQueryDictionary")])
		{
			NSMutableArray* plugins = result[key];
			NSLog(@"plugins bundle count=%ld", plugins.count);

			NSMutableIndexSet* removed = [[NSMutableIndexSet alloc] init];
			for (int i=0; i<[plugins count]; i++) 
			{
				id plugin = plugins[i]; //LSPlugInKitProxy
				id appbundle = [plugin performSelector:@selector(containingBundle)];
				// NSLog(@"plugin=%@, %@", plugin, appbundle);
				if(!appbundle) continue;

				NSURL* bundleURL = [appbundle performSelector:@selector(bundleURL)];
				if(isJailbreakPath(bundleURL.path.fileSystemRepresentation)) {
					NSLog(@"remove plugin %@ (%@)", plugin, bundleURL);
					[removed addIndex:i];
				}
			}

			[plugins removeObjectsAtIndexes:removed];
			NSLog(@"new plugins bundle count=%ld", plugins.count);

			if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")])
			{
				//NSLog(@"_pluginUnits=%@", [key valueForKey:@"_pluginUnits"]);
				NSLog(@"LSPlugInQueryWithUnits: _pluginUnits count=%ld", [[key valueForKey:@"_pluginUnits"] count]);

				NSMutableArray* units = [[key valueForKey:@"_pluginUnits"] mutableCopy];
				[units removeObjectsAtIndexes:removed];
				[key setValue:[units copy] forKey:@"_pluginUnits"];

				NSLog(@"LSPlugInQueryWithUnits: new _pluginUnits count=%ld", [[key valueForKey:@"_pluginUnits"] count]);
			}
			else if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithQueryDictionary")])
			{
				NSLog(@"LSPlugInQueryWithQueryDictionary: _queryDict=%@", [key valueForKey:@"_queryDict"]);
				NSLog(@"LSPlugInQueryWithQueryDictionary: _extensionIdentifiers=%@", [key valueForKey:@"_extensionIdentifiers"]);
				NSLog(@"LSPlugInQueryWithQueryDictionary: _extensionPointIdentifiers=%@", [key valueForKey:@"_extensionPointIdentifiers"]);
			}
			else if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithIdentifier")])
			{
				NSLog(@"LSPlugInQueryWithIdentifier: _identifier=%@", [key valueForKey:@"_identifier"]);
			}
		}
		else if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryAllUnits")])
		{
			NSMutableArray* unitsArray = result[key];
			for (int i=0; i<[unitsArray count]; i++)
			{
				id unitsResult = unitsArray[i]; //LSPlugInQueryAllUnitsResult

				NSUUID* _dbUUID = [unitsResult valueForKey:@"_dbUUID"];
				NSArray* _pluginUnits = [unitsResult valueForKey:@"_pluginUnits"];
				NSLog(@"LSPlugInQueryAllUnits: _dbUUID=%@, _pluginUnits count=%ld", _dbUUID, _pluginUnits.count);
				id unitQuery = [[NSClassFromString(@"LSPlugInQueryWithUnits") alloc] initWithPlugInUnits:_pluginUnits forDatabaseWithUUID:_dbUUID];
				NSMutableDictionary* queriesResult = [self _resolveQueries:[NSSet setWithObject:unitQuery] XPCConnection:xpc error:err];
				if(queriesResult)
				{
					for(id queryKey in queriesResult)
					{
						NSArray* new_pluginUnits = [queryKey valueForKey:@"_pluginUnits"];
						[unitsResult setValue:new_pluginUnits forKey:@"_pluginUnits"];
						NSLog(@"LSPlugInQueryAllUnits: new _pluginUnits count=%ld", new_pluginUnits.count);
					}
				}
			}
		}
	}

	return result;
}

%end


//or -[Copier initWithSourceURL:uniqueIdentifier:destURL:callbackTarget:selector:options:] in transitd
NSURL* (*orig_LSGetInboxURLForBundleIdentifier)(NSString* bundleIdentifier)=NULL;
NSURL* new_LSGetInboxURLForBundleIdentifier(NSString* bundleIdentifier)
{
	NSURL* pathURL = orig_LSGetInboxURLForBundleIdentifier(bundleIdentifier);

	if( ![bundleIdentifier hasPrefix:@"com.apple."] 
			&& [pathURL.path hasPrefix:@"/var/mobile/Library/Application Support/Containers/"])
	{
		NSLog(@"redirect Inbox %@ : %@", bundleIdentifier, pathURL);
		pathURL = [NSURL fileURLWithPath:jbroot(pathURL.path)]; //require unsandboxing file-write-read for jbroot:/var/
	}

	return pathURL;
}

int (*orig_LSServer_RebuildApplicationDatabases)()=NULL;
int new_LSServer_RebuildApplicationDatabases()
{
	int r = orig_LSServer_RebuildApplicationDatabases();

	if(access(jbroot("/.disable_auto_uicache"), F_OK) == 0) return r;

	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		// Ensure jailbreak apps are readded to icon cache after the system reloads it
		// A bit hacky, but works
		char* const args[] = {"/usr/bin/uicache", "-a", NULL};
		const char *uicachePath = jbroot(args[0]);
		if (access(uicachePath, F_OK) == 0) {
			posix_spawn(NULL, uicachePath, NULL, NULL, args, environ);
		}
	});

	return r;
}

void lsdInit(void)
{
	NSLog(@"lsdInit...");

	MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");

	void* _LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier");
	NSLog(@"coreServicesImage=%p, _LSGetInboxURLForBundleIdentifier=%p", coreServicesImage, _LSGetInboxURLForBundleIdentifier);
	if(_LSGetInboxURLForBundleIdentifier)
	{
		MSHookFunction(_LSGetInboxURLForBundleIdentifier, (void *)&new_LSGetInboxURLForBundleIdentifier, (void **)&orig_LSGetInboxURLForBundleIdentifier);
	}
	
	void* _LSServer_RebuildApplicationDatabases = MSFindSymbol(coreServicesImage, "__LSServer_RebuildApplicationDatabases");
	NSLog(@"coreServicesImage=%p, _LSServer_RebuildApplicationDatabases=%p", coreServicesImage, _LSServer_RebuildApplicationDatabases);
	if(_LSServer_RebuildApplicationDatabases)
	{
		MSHookFunction(_LSServer_RebuildApplicationDatabases, (void *)&new_LSServer_RebuildApplicationDatabases, (void **)&orig_LSServer_RebuildApplicationDatabases);
	}

	%init();
}
