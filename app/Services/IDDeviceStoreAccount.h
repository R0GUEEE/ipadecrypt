#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// IDDeviceStoreAccount reads the App Store identity the phone is already
// signed in with.
//
// The on-device helper cannot perform an Apple ID *login*. Apple requires an
// X-Apple-ActionSignature on the authenticate request, and the only thing that
// can produce one is SAP - which runs a prebuilt x86_64 Unicorn library that
// has no iOS build at all. Every other App Store call is sent unsigned and
// authenticates from the session cookies, so the app hands the helper the
// device's own App Store session instead of a password.
//
// Everything here is best effort and must stay safe when StoreServices is
// missing or answers differently than expected: the helper copes with a
// partial identity, and falls back to its old behaviour when it gets none.
@interface IDDeviceStoreAccount : NSObject

// Directory Services person id (the numeric Apple ID) of the signed-in
// account, or nil when it cannot be read. Never logged - it is a personal
// identifier.
+ (nullable NSString *)directoryServicesIdentifier;

// Two-letter storefront country code for the device, or nil. Read from
// NSLocale, so it needs no private framework.
+ (nullable NSString *)storeFrontCountryCode;

// The numeric App Store storefront (e.g. 143441) when StoreServices reports
// one, or nil.
+ (nullable NSString *)storeFrontIdentifier;

// Arguments that switch appstore-helper to the device's own session. Always
// safe to append: --device-session is unconditional, the identity flags are
// omitted when unknown.
+ (NSArray<NSString *> *)helperArguments;

@end

NS_ASSUME_NONNULL_END
