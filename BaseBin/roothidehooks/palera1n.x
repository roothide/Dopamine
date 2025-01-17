#import <Foundation/Foundation.h>
#import <substrate.h>
#include <roothide.h>

#ifndef DEBUG
#define NSLog(args...)	
#endif

#define kMobileKeyBagError (-1)
#define kMobileKeyBagDeviceIsUnlocked 0
#define kMobileKeyBagDeviceIsLocked 1
#define kMobileKeyBagDeviceLocking 2
#define kMobileKeyBagDisabled 3

%group coreauthd

%hookf(int, MKBGetDeviceLockState, CFDictionaryRef options)
{
	int ret = %orig;

	NSLog(@"MKBGetDeviceLockState: %@ -> %d", options, ret);

	if(ret == kMobileKeyBagDisabled) {
        ret = kMobileKeyBagDeviceIsUnlocked;
	}

	return ret;
}

%hookf(CFDictionaryRef, MKBGetDeviceLockStateInfo, CFDictionaryRef options)
{
	CFDictionaryRef ret = %orig;

	NSMutableDictionary* newret = ((__bridge NSDictionary*)ret).mutableCopy;

	if([newret[@"ls"] longValue] == kMobileKeyBagDisabled)
	{
        newret[@"ls"] = @(kMobileKeyBagDeviceIsUnlocked);
	}

	NSLog(@"MKBGetDeviceLockStateInfo: %@ -> %@ -> %@", options, ret, newret);

	CFRelease(ret);
	return CFRetain((__bridge CFDictionaryRef)newret);
}

%end

%group securityd 

%hookf(Boolean, CFEqual, CFTypeRef cf1, CFTypeRef cf2)
{
	if(cf1==kSecAttrAccessibleWhenUnlockedThisDeviceOnly || cf2==kSecAttrAccessibleWhenUnlockedThisDeviceOnly) {
		if(%orig(cf1, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) || %orig(cf2, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)) {
            NSLog(@"hijacking %@ : %@", cf1, cf2);
			return YES; //akpu->aku
		}
	}
	else if(cf1==kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly || cf2==kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) {
        NSLog(@"preventing %@ : %@", cf1, cf2);
		return NO;
	}

	return %orig;
}

%end

%group ctkd

%hookf(CFTypeRef, SecAccessControlGetProtection, SecAccessControlRef access_control)
{
	CFTypeRef ret = %orig;

	CFTypeRef newret = ret;
	if(CFEqual(ret, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)) {
		newret = kSecAttrAccessibleWhenUnlockedThisDeviceOnly; //akpu->aku
	}
	NSLog(@"SecAccessControlGetProtection %@->%@ : %@", ret, newret, access_control);
	ret = newret;
	return ret;
}

%end

void palera1nInit(NSString* processName)
{
    NSLog(@"palera1nInit %@", processName);
    if ([processName isEqualToString:@"coreauthd"]) {
	    MSImageRef MobileKeyBagImage = MSGetImageByName("/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag");
        %init(coreauthd, MKBGetDeviceLockState = MSFindSymbol(MobileKeyBagImage, "_MKBGetDeviceLockState"), MKBGetDeviceLockStateInfo = MSFindSymbol(MobileKeyBagImage, "_MKBGetDeviceLockStateInfo"));
    }
    else if ([processName isEqualToString:@"securityd"]) {
        %init(securityd);
    }
    else if ([processName isEqualToString:@"ctkd"]) {
	    MSImageRef SecurityFramework = MSGetImageByName("/System/Library/Frameworks/Security.framework/Security");
        %init(ctkd, SecAccessControlGetProtection = MSFindSymbol(SecurityFramework, "_SecAccessControlGetProtection"));
	}
}
