#import "IDDeviceStoreAccount.h"
#import "Logging.h"
#import <dispatch/dispatch.h>
#import <dlfcn.h>

// StoreServices is a private framework, so it is loaded at runtime and reached
// through -performSelector / dynamic messaging rather than a link-time
// dependency. A missing framework degrades to "no device session", never to a
// crash.
static void *IDStoreServicesHandle(void) {
    static void *handle = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        handle = dlopen("/System/Library/PrivateFrameworks/StoreServices.framework/StoreServices", RTLD_NOW);
        if (!handle) {
            IDLOG(@"StoreServices unavailable: %s", dlerror() ?: "unknown");
        }
    });
    return handle;
}

static id IDCall(id receiver, NSString *selectorName) {
    if (!receiver) return nil;
    SEL selector = NSSelectorFromString(selectorName);
    if (![receiver respondsToSelector:selector]) return nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    return [receiver performSelector:selector];
#pragma clang diagnostic pop
}

@implementation IDDeviceStoreAccount

+ (nullable NSString *)stringFromObject:(id)value {
    if ([value isKindOfClass:[NSString class]]) {
        return [(NSString *)value length] ? (NSString *)value : nil;
    }
    if ([value isKindOfClass:[NSNumber class]]) {
        return [(NSNumber *)value stringValue];
    }
    return nil;
}

+ (id)defaultAccount {
    if (!IDStoreServicesHandle()) return nil;

    Class storeClass = NSClassFromString(@"SSAccountStore");
    if (!storeClass) return nil;

    id store = IDCall(storeClass, @"defaultStore");
    if (!store) {
        store = IDCall(storeClass, @"defaultAccountStore");
    }

    return IDCall(store, @"defaultAccount");
}

+ (nullable NSString *)directoryServicesIdentifier {
    id account = [self defaultAccount];
    if (!account) return nil;

    // accountProperties is the canonical bag of account fields; DsPersonId is
    // the Directory Services id the App Store wants in X-Dsid.
    id properties = IDCall(account, @"accountProperties");
    if ([properties isKindOfClass:[NSDictionary class]]) {
        for (NSString *key in @[@"DsPersonId", @"dsPersonId", @"dsid", @"DSID"]) {
            NSString *value = [self stringFromObject:[(NSDictionary *)properties objectForKey:key]];
            if (value.length) return value;
        }
    }

    // Fall back to the account's own identifier, which is the same number on
    // every iOS version we target.
    NSString *unique = [self stringFromObject:IDCall(account, @"uniqueIdentifier")];
    if (unique.length && ![unique isEqualToString:@"0"]) {
        return unique;
    }

    return nil;
}

+ (nullable NSString *)storeFrontCountryCode {
    NSString *code = [[NSLocale currentLocale] objectForKey:NSLocaleCountryCode];
    return code.length ? [code uppercaseString] : nil;
}

+ (nullable NSString *)storeFrontIdentifier {
    if (IDStoreServicesHandle()) {
        Class deviceClass = NSClassFromString(@"SSDevice");
        id device = IDCall(deviceClass, @"currentDevice");
        NSString *raw = [self stringFromObject:IDCall(device, @"storeFrontIdentifier")];
        if (raw.length) {
            // Apple reports "<id>-<region>,<n>"; keep the numeric head only.
            NSMutableString *digits = [NSMutableString string];
            for (NSUInteger i = 0; i < raw.length; i++) {
                unichar c = [raw characterAtIndex:i];
                if (c < '0' || c > '9') break;
                [digits appendFormat:@"%C", c];
            }
            if (digits.length) return digits;
        }
    }

    return nil;
}

+ (NSArray<NSString *> *)helperArguments {
    NSMutableArray<NSString *> *args = [NSMutableArray arrayWithObject:@"--device-session"];

    NSString *dsid = [self directoryServicesIdentifier];
    if (dsid.length) {
        [args addObjectsFromArray:@[@"--dsid", dsid]];
    }

    // Prefer the numeric storefront; a country code resolves on the Go side.
    NSString *storeFront = [self storeFrontIdentifier];
    if (!storeFront.length) {
        storeFront = [self storeFrontCountryCode];
    }
    if (storeFront.length) {
        [args addObjectsFromArray:@[@"--storefront", storeFront]];
    }

    IDLOG(@"device session arguments: dsid=%@ storefront=%@",
          dsid.length ? @"present" : @"missing",
          storeFront.length ? storeFront : @"missing");

    return args;
}

@end
