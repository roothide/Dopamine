#import <Foundation/Foundation.h>
#import <substrate.h>
#include <roothide.h>


BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
	if ( [plistPath hasPrefix:@"/var/db/"]
	  || [plistPath hasPrefix:@"/private/var/preferences/"]
	  || [plistPath hasPrefix:@"/private/var/mobile/Containers/"] ) 
	  return NO;

	NSString *plistName = plistPath.lastPathComponent;

	NSArray* appleInternalBundleIds = @[
		@"com.apple.Terminal.plist",
	];

	if ([appleInternalBundleIds containsObject:plistName])
		return YES;

	if ([plistName hasPrefix:@"com.apple."]
	  || [plistName hasPrefix:@"group.com.apple."]
	 || [plistName hasPrefix:@"systemgroup.com.apple."])
	  return NO;

	NSArray *additionalSystemPlistNames = @[
		@".GlobalPreferences.plist",
		@".GlobalPreferences_m.plist",
		@"bluetoothaudiod.plist",
		@"NetworkInterfaces.plist",
		@"OSThermalStatus.plist",
		@"preferences.plist",
		@"osanalyticshelper.plist",
		@"UserEventAgent.plist",
		@"wifid.plist",
		@"dprivacyd.plist",
		@"silhouette.plist",
		@"nfcd.plist",
		@"kNPProgressTrackerDomain.plist",
		@"siriknowledged.plist",
		@"UITextInputContextIdentifiers.plist",
		@"mobile_storage_proxy.plist",
		@"splashboardd.plist",
		@"mobile_installation_proxy.plist",
		@"languageassetd.plist",
		@"ptpcamerad.plist",
		@"com.google.gmp.measurement.monitor.plist",
		@"com.google.gmp.measurement.plist",
	];

	return ![additionalSystemPlistNames containsObject:plistName];
}

BOOL (*orig_CFPrefsGetPathForTriplet)(CFStringRef, CFStringRef, BOOL, CFStringRef, UInt8*);
BOOL new_CFPrefsGetPathForTriplet(CFStringRef bundleIdentifier, CFStringRef user, BOOL byHost, CFStringRef path, UInt8 *buffer)
{
	BOOL orig = orig_CFPrefsGetPathForTriplet(bundleIdentifier, user, byHost, path, buffer);

	NSLog(@"CFPrefsGetPathForTriplet %@ %@ %d %@ : %d %s", bundleIdentifier, user, byHost, path, orig, orig?(char*)buffer:"");

	if(orig && buffer)
	{
		NSString* origPath = [NSString stringWithUTF8String:(char*)buffer];
		BOOL needsRedirection = preferencePlistNeedsRedirection(origPath);
		if (needsRedirection) {
			NSLog(@"Plist redirected to jbroot: %@", origPath);
			const char* newpath = jbroot(origPath.UTF8String);
			//buffer size=1024 in CFXPreferences_fileProtectionClassForIdentifier_user_host_container___block_invoke
			if(strlen(newpath) < 1024) {
				strcpy((char*)buffer, newpath);
				NSLog(@"CFPrefsGetPathForTriplet redirect to %s", buffer);
			}
		}
	}

	return orig;
}

void cfprefsdInit(void)
{
	NSLog(@"cfprefsdInit..");

	MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
	void* CFPrefsGetPathForTriplet_ptr = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet");
	if(CFPrefsGetPathForTriplet_ptr)
	{
		MSHookFunction(CFPrefsGetPathForTriplet_ptr, (void *)&new_CFPrefsGetPathForTriplet, (void **)&orig_CFPrefsGetPathForTriplet);
		NSLog(@"hook __CFPrefsGetPathForTriplet %p => %p : %p", CFPrefsGetPathForTriplet_ptr, new_CFPrefsGetPathForTriplet, orig_CFPrefsGetPathForTriplet);
	}

	%init();
}
