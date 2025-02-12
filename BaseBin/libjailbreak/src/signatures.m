#include <choma/FAT.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <mach-o/dyld.h>
#include "trustcache.h"

#import <Foundation/Foundation.h>

MachO *ljb_fat_find_preferred_slice(FAT *fat)
{
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return NULL; }
	
	MachO *candidateSlice = NULL;

	if (cpusubtype == CPU_SUBTYPE_ARM64E) {
		// New arm64e ABI
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
		if (!candidateSlice) {
			// Old arm64e ABI
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E);
			if (candidateSlice) {
				// If we found an old arm64e slice, make sure this is a library! If it's a binary, skip!!!
				// For binaries the system will fall back to the arm64 slice, which has the CDHash that we want to add
				if (macho_get_filetype(candidateSlice) == MH_EXECUTE) candidateSlice = NULL;
			}
		}
	}

	if (!candidateSlice) {
		// On iOS 15+ the kernels prefers ARM64_V8 to ARM64_ALL
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_V8);
		if (!candidateSlice) {
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_ALL);
		}
	}

	return candidateSlice;
}

bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
	CS_DecodedBlob *wrapperBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
	if (wrapperBlob) {
		if (csd_blob_get_size(wrapperBlob) > 8) {
			return false;
		}
	}
	return true;
}


#include <choma/MachOByteOrder.h>
#include <choma/CodeDirectory.h>
#include <libgen.h>
#include "util.h"
#include "log.h"

extern CS_DecodedBlob *csd_superblob_find_best_code_directory(CS_DecodedSuperBlob *decodedSuperblob);
extern bool csd_code_directory_calculate_page_hash(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot, uint8_t *pageHashOut);

FAT *fat_init_for_writing(const char *filePath)
{
    MemoryStream *stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE);
    if (stream) {
        return fat_init_from_memory_stream(stream);;
    }
    return NULL;
}

int calc_cdhash(uint8_t *cdBlob, size_t cdBlobSize, uint8_t hashtype, void *cdhashOut)
{
    // Longest possible buffer, will cut it off at the end as cdhash size is fixed
    uint8_t cdhash[CC_SHA384_DIGEST_LENGTH];

    JBLogDebug("head=%llx  %lx\n", *(uint64_t*)cdBlob, cdBlobSize);

    switch (hashtype) {
		case CS_HASHTYPE_SHA160_160: {
			CC_SHA1(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}
		
		case CS_HASHTYPE_SHA256_256:
		case CS_HASHTYPE_SHA256_160: {
			CC_SHA256(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

		case CS_HASHTYPE_SHA384_384: {
			CC_SHA384(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

        default:
        return -1;
	}

    memcpy(cdhashOut, cdhash, CS_CDHASH_LEN);
    return 0;
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

bool is_app_path(const char* path)
{
    if(!path) return false;

    char rp[PATH_MAX];
    if(!realpath(path, rp)) return false;

    if(strncmp(rp, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return false;

    char* p1 = rp + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return false;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return false;

	return true;
}

int ensure_randomized_cdhash(const char* inputPath, void* cdhashOut)
{
	if(access(inputPath, W_OK) != 0)
		return -1;
		
	// Initialise the FAT structure
    JBLogDebug("Initialising FAT structure from %s.\n", inputPath);
    FAT *fat = fat_init_for_writing(inputPath);
    if (!fat) return -1;

    MachO *macho = ljb_fat_find_preferred_slice(fat);
	if(!macho) {
		fat_free(fat);
		return -1;
	}
    JBLogDebug("preferred slice: %llx\n", macho->archDescriptor.offset);

	__block int foundCount = 0;
    __block uint64_t textsegoffset = 0;
    __block uint64_t firstsectoffset = 0;
	__block struct section_64 firstsection={0};
    __block struct segment_command_64 textsegment={0};
    __block struct linkedit_data_command linkedit={0};

    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		bool foundOne = false;
		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 *segmentCommand = ((struct segment_command_64 *)cmd);

			if (strcmp(segmentCommand->segname, "__TEXT") != 0) return;

			textsegoffset = offset;
			textsegment = *segmentCommand;

			if(segmentCommand->nsects==0) {
				*stop=true;
				return;
			}

			firstsectoffset = textsegoffset + sizeof(*segmentCommand);
			firstsection = *(struct section_64*)((uint64_t)segmentCommand + sizeof(*segmentCommand));
			if (strcmp(firstsection.segname, "__TEXT") != 0) {
				*stop=true;
				return;
			}
			
			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
		if (loadCommand.cmd == LC_CODE_SIGNATURE) {
			struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
			JBLogDebug("LC_CODE_SIGNATURE: %x\n", csLoadCommand->dataoff);

			linkedit = *csLoadCommand;

			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
    });

    if(foundCount < 2) {
		fat_free(fat);
		return -1;
	}

    uint64_t* rd = (uint64_t*)&(textsegment.segname[sizeof(textsegment.segname)-sizeof(uint64_t)]);
    uint64_t* rd2 = (uint64_t*)&(firstsection.segname[sizeof(firstsection.segname)-sizeof(uint64_t)]);
    JBLogDebug("__TEXT: %llx,%llx, %016llX %016llX\n", textsegoffset, textsegment.fileoff, *rd, *rd2);

	bool isAppPath = is_app_path(inputPath);

    int retval=-1;

    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        JBLogDebug("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
		fat_free(fat);
        return -1;
    }

    JBLogDebug("super blob: %x %x %d\n", superblob->magic, BIG_TO_HOST(superblob->length), BIG_TO_HOST(superblob->count));

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	if(!decodedSuperblob) {
		free(superblob);
		fat_free(fat);
		return -1;
	}

	do
	{
		CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
		if(!bestCDBlob) break;

		if( (isAppPath && *rd==0 && *rd2==0) //Ignore macho for installable apps (removable system apps or other stuff)
			|| (!isAppPath && *rd==0 && *rd2 == jbinfo(jbrand)) ) 
		{
			retval = csd_code_directory_calculate_hash(bestCDBlob, cdhashOut);
			break;
		}

		if(*rd != 0) //fix it patched on previous version
		{
			*rd = 0;
			if(memory_stream_write(fat->stream, macho->archDescriptor.offset + textsegoffset, sizeof(textsegment), &textsegment) != 0) {
				break;
			}
		}

		if(isAppPath) {
			*rd2 = 0; //fix removable system apps patched on previous version
		} else {
			*rd2 = jbinfo(jbrand);
		}
		if(memory_stream_write(fat->stream, macho->archDescriptor.offset + firstsectoffset, sizeof(firstsection), &firstsection) != 0) {
			break;
		}
				
		CS_CodeDirectory codeDir;
		if(csd_blob_read(bestCDBlob, 0, sizeof(CS_CodeDirectory), &codeDir) != 0) {
			break;
		}

		CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

		uint8_t pageHash[codeDir.hashSize];
		if(!csd_code_directory_calculate_page_hash(bestCDBlob, macho, 0, pageHash)) {
			break;
		}

		for (uint32_t i = 0; i < BIG_TO_HOST(superblob->count); i++) {
			CS_BlobIndex curIndex = superblob->index[i];
			BLOB_INDEX_APPLY_BYTE_ORDER(&curIndex, BIG_TO_HOST_APPLIER);
			//JBLogDebug("decoding %u (type: %x, offset: 0x%x)\n", i, curIndex.type, curIndex.offset);

			if(curIndex.type == bestCDBlob->type)
			{
				if(0 != memory_stream_write(fat->stream, macho->archDescriptor.offset + linkedit.dataoff + curIndex.offset + codeDir.hashOffset, codeDir.hashSize, pageHash)) {
					break;
				}

				void* newCDBlob = malloc(codeDir.length);

				if(memory_stream_read(fat->stream, macho->archDescriptor.offset + linkedit.dataoff + curIndex.offset, codeDir.length, newCDBlob) == 0) {

					retval = calc_cdhash(newCDBlob, codeDir.length, csd_code_directory_get_hash_type(bestCDBlob), cdhashOut);
				
				}

				free(newCDBlob);

				break;
			}
		}

	} while(0);

	csd_superblob_free(decodedSuperblob);
	free(superblob);
	fat_free(fat);

	return retval;
}

void ensure_jbroot_symlink(const char* filepath)
{
	JBLogDebug("ensure_jbroot_symlink: %s", filepath);

	if(access(filepath, F_OK) !=0 )
		return;

	char realfpath[PATH_MAX];
	assert(realpath(filepath, realfpath) != NULL);

	char realdirpath[PATH_MAX+1];
	dirname_r(realfpath, realdirpath);
	if(realdirpath[strlen(realdirpath)] != '/') strcat(realdirpath, "/");

	char jbrootpath[PATH_MAX+1];
	assert(realpath(JBROOT_PATH("/"), jbrootpath) != NULL);
	if(jbrootpath[strlen(jbrootpath)] != '/') strcat(jbrootpath, "/");

	JBLogDebug("%s : %s", realdirpath, jbrootpath);

	if(strncmp(realdirpath, jbrootpath, strlen(jbrootpath)) != 0) 
		return;

	struct stat jbrootst;
	assert(stat(jbrootpath, &jbrootst) == 0);
	
	char sympath[PATH_MAX];
	snprintf(sympath,sizeof(sympath),"%s/.jbroot", realdirpath);

	struct stat symst;
	if(lstat(sympath, &symst)==0)
	{
		if(S_ISLNK(symst.st_mode))
		{
			if(stat(sympath, &symst) == 0)
			{
				if(symst.st_dev==jbrootst.st_dev 
					&& symst.st_ino==jbrootst.st_ino)
					return;
			}

			assert(unlink(sympath) == 0);
			
		} else {
			//not a symlink? just let it go
			return;
		}
	}

	if(symlink(jbrootpath, sympath) ==0 ) {
		JBLogError("update .jbroot @ %s\n", sympath);
	} else {
		JBLogError("symlink error @ %s\n", sympath);
	}
}
/////////////////////////////////////////////////////////

NSString *resolveDependencyPath(NSString *dylibPath, NSString *sourceImagePath, NSString *sourceExecutablePath)
{
	@autoreleasepool {
		if (!dylibPath) return nil;
		NSString *loaderPath = [sourceImagePath stringByDeletingLastPathComponent];
		NSString *executablePath = [sourceExecutablePath stringByDeletingLastPathComponent];

		NSString *resolvedPath = nil;

		NSString *(^resolveLoaderExecutablePaths)(NSString *) = ^NSString *(NSString *candidatePath) {
			if (!candidatePath) return nil;
			if ([[NSFileManager defaultManager] fileExistsAtPath:candidatePath]) return candidatePath;
			if ([candidatePath hasPrefix:@"@loader_path"] && loaderPath) {
				NSString *loaderCandidatePath = [candidatePath stringByReplacingOccurrencesOfString:@"@loader_path" withString:loaderPath];
				if ([[NSFileManager defaultManager] fileExistsAtPath:loaderCandidatePath]) return loaderCandidatePath;
			}
			if ([candidatePath hasPrefix:@"@executable_path"] && executablePath) {
				NSString *executableCandidatePath = [candidatePath stringByReplacingOccurrencesOfString:@"@executable_path" withString:executablePath];
				if ([[NSFileManager defaultManager] fileExistsAtPath:executableCandidatePath]) return executableCandidatePath;
			}
			return nil;
		};

		if ([dylibPath hasPrefix:@"@rpath"]) {
			NSString *(^resolveRpaths)(NSString *) = ^NSString *(NSString *binaryPath) {
				if (!binaryPath) return nil;
				__block NSString *rpathResolvedPath = nil;
				FAT *fat = fat_init_from_path(binaryPath.fileSystemRepresentation);
				if (fat) {
					MachO *macho = ljb_fat_find_preferred_slice(fat);
					if (macho) {
						macho_enumerate_rpaths(macho, ^(const char *rpathC, bool *stop) {
							if (rpathC) {
								NSString *rpath = [NSString stringWithUTF8String:rpathC];
								if (rpath) {
									rpathResolvedPath = resolveLoaderExecutablePaths([dylibPath stringByReplacingOccurrencesOfString:@"@rpath" withString:rpath]);
									if (rpathResolvedPath) {
										*stop = true;
									}
								}
							}
						});
					}
					fat_free(fat);
				}
				return rpathResolvedPath;
			};

			resolvedPath = resolveRpaths(sourceImagePath);
			if (resolvedPath) return resolvedPath;

			// TODO: Check if this is even neccessary
			resolvedPath = resolveRpaths(sourceExecutablePath);
			if (resolvedPath) return resolvedPath;
		}
		else {
			resolvedPath = resolveLoaderExecutablePaths(dylibPath);
			if (resolvedPath) return resolvedPath;
		}
		
		return nil;
	}
}

void macho_collect_untrusted_cdhashes(const char *path, const char *callerImagePath, const char *callerExecutablePath, uint32_t *preferredArchTypes, uint32_t *preferredArchSubtypes, size_t preferredArchCount, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	@autoreleasepool {
		if (!path) return;

		__block cdhash_t *cdhashes = NULL;
		__block uint32_t cdhashCount = 0;

		bool (^cdhashesContains)(cdhash_t) = ^bool(cdhash_t cdhash) {
			for (int i = 0; i < cdhashCount; i++) {
				if (!memcmp(cdhashes[i], cdhash, sizeof(cdhash_t))) {
					return true;
				}
			}
			return false;
		};

		void (^cdhashesAdd)(cdhash_t) = ^(cdhash_t cdhash) {
			cdhashCount++;
			cdhashes = realloc(cdhashes, cdhashCount * sizeof(cdhash_t));
			memcpy(cdhashes[cdhashCount-1], cdhash, sizeof(cdhash_t));
		};

		if (!callerExecutablePath) {
			FAT *mainFAT = fat_init_from_path(path);
			if (mainFAT) {
				MachO *mainMachO = NULL;
				if (preferredArchCount > 0) {
					for (size_t i = 0; i < preferredArchCount; i++) {
						if (preferredArchTypes[i] != 0 && preferredArchSubtypes[i] != UINT32_MAX) {
							mainMachO = fat_find_slice(mainFAT, preferredArchTypes[i], preferredArchSubtypes[i]);
							if (mainMachO) break;
						}
					}	
				}
				if (!mainMachO) mainMachO = ljb_fat_find_preferred_slice(mainFAT);
				if (mainMachO) {
					if (macho_get_filetype(mainMachO) == MH_EXECUTE) {
						callerExecutablePath = path;
					}
				}
				fat_free(mainFAT);
			}
		}
		if (!callerImagePath) {
			if (!access(path, F_OK)) {
				callerImagePath = path;
			}
		}

		__weak __block void (^binaryTrustHandler_recurse)(NSString *, NSString *, NSString *);
		void (^binaryTrustHandler)(NSString *, NSString *, NSString *) = ^(NSString *binaryPath, NSString *sourceImagePath, NSString *sourceExecutablePath) {
			NSString *resolvedBinaryPath = resolveDependencyPath(binaryPath, sourceImagePath, sourceExecutablePath);
			
			ensure_jbroot_symlink(resolvedBinaryPath.fileSystemRepresentation);

			FAT *fat = fat_init_from_path(resolvedBinaryPath.fileSystemRepresentation);
			if (!fat) return;
			MachO *macho = NULL;
			if ([binaryPath isEqualToString:sourceExecutablePath]) {
				if (preferredArchCount > 0) {
					for (size_t i = 0; i < preferredArchCount; i++) {
						if (preferredArchTypes[i] != 0 && preferredArchSubtypes[i] != UINT32_MAX) {
							macho = fat_find_slice(fat, preferredArchTypes[i], preferredArchSubtypes[i]);
							if (macho) break;
						}
					}
				}
			}
			if (!macho) macho = ljb_fat_find_preferred_slice(fat);
			if (!macho) {
				fat_free(fat);
				return;
			}

			// Calculate cdhash and add it to our array
			bool cdhashWasKnown = true;
			bool isAdhocSigned = false;
			CS_SuperBlob *superblob = macho_read_code_signature(macho);
			if (superblob) {
				CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
				if (decodedSuperblob) {
					if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
						isAdhocSigned = true;
						cdhash_t cdhash;
						if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhash) == 0) {
							if (!cdhashesContains(cdhash)) {
								if (!is_cdhash_trustcached(cdhash)) {
									// If something is trustcached we do not want to add it to your array
									// We do want to parse it's dependencies however, as one may have been updated since we added the binary to trustcache
									// Potential optimization: If trustcached, save in some array so we don't recheck

									int ret = 0;
									if(preferredArchCount == 0) {
										ret = ensure_randomized_cdhash(resolvedBinaryPath.fileSystemRepresentation, cdhash);
										JBLogDebug("ensure_randomized_cdhash: %s (%d)", resolvedBinaryPath.fileSystemRepresentation, ret);
									}
									if(ret==0) cdhashesAdd(cdhash);
								}
								cdhashWasKnown = false;
							}
						}
					}
					csd_superblob_free(decodedSuperblob);
				}
				free(superblob);
			}

			if (cdhashWasKnown || // If we already knew the cdhash, we can skip parsing dependencies
				!isAdhocSigned) { // If it was not ad hoc signed, we can safely skip it aswell
				fat_free(fat);
				return;
			}

			// Recurse this block on all dependencies
			macho_enumerate_dependencies(macho, ^(const char *dylibPathC, uint32_t cmd, struct dylib* dylib, bool *stop) {
				if (!dylibPathC) return;
				if (_dyld_shared_cache_contains_path(dylibPathC)) return;
				binaryTrustHandler_recurse([NSString stringWithUTF8String:dylibPathC], resolvedBinaryPath, sourceExecutablePath);
			});

			fat_free(fat);
		};
		binaryTrustHandler_recurse = binaryTrustHandler;

		binaryTrustHandler([NSString stringWithUTF8String:path], callerImagePath ? [NSString stringWithUTF8String:callerImagePath] : nil, callerExecutablePath ? [NSString stringWithUTF8String:callerExecutablePath] : nil);

		*cdhashesOut = cdhashes;
		*cdhashCountOut = cdhashCount;
	}
}