//
//  Keychain.m
//  CryptoPill
//
//  Created by Sébastien Martini on 16/08/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "Keychain.h"

@import Security;

#import "NSData+Digest.h"
#import "SecureData.h"


@implementation Keychain

#pragma mark - Add keys

+ (BOOL)addKey:(NSData *)key withAttributes:(NSDictionary *)attrs {
  if (!key ||
      attrs[(__bridge id)(kSecAttrKeyClass)] == nil ||
      attrs[(__bridge id)(kSecAttrApplicationLabel)] == nil)
    return NO;

  NSMutableDictionary *fullAttrs = [NSMutableDictionary dictionaryWithDictionary:attrs];
  fullAttrs[(__bridge __strong id)(kSecClass)] = (__bridge id)(kSecClassKey);
  fullAttrs[(__bridge __strong id)(kSecValueData)] = key;
  if (fullAttrs[(__bridge id)(kSecAttrIsPermanent)] == nil)
    fullAttrs[(__bridge __strong id)(kSecAttrIsPermanent)] = @(YES);

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)(fullAttrs), NULL);
  if (status != errSecSuccess) {
    NSLog(@"Error cannot add key with app label %@ to keychain, OSStatus == %d.",
          attrs[(__bridge id)(kSecAttrApplicationLabel)], (int)status);
    return NO;
  }
  return YES;
}


+ (BOOL)addPublicKey:(NSData *)publickKey
withApplicationLabel:(NSString *)applicationLabel
             withTag:(NSData *)tag
           withLabel:(NSString *)label
    forAccessibility:(CFTypeRef)accessibility {
  if (!publickKey)
    return NO;

  NSMutableDictionary *attrs = [NSMutableDictionary dictionary];
  attrs[(__bridge __strong id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPublic;
  attrs[(__bridge __strong id)kSecAttrAccessible] = (__bridge id)accessibility;
  if (!applicationLabel)
    applicationLabel = [publickKey stringSHA256];
  attrs[(__bridge __strong id)kSecAttrApplicationLabel] = applicationLabel;
  if (tag)
    attrs[(__bridge __strong id)kSecAttrApplicationTag] = tag;
  if (label)
    attrs[(__bridge __strong id)kSecAttrLabel] = label;
  return [self addKey:publickKey withAttributes:attrs];
}

// Actually not used, can be removed.
+ (BOOL)addPublicKey:(NSData *)publickKey withApplicationLabel:(NSString *)applicationLabel withTag:(NSData *)tag {
  return [self addPublicKey:publickKey
       withApplicationLabel:applicationLabel
                    withTag:tag
                  withLabel:nil
           forAccessibility:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly];
}


+ (BOOL)addPrivateKey:(SecureData *)privateKey
 withApplicationLabel:(NSString *)applicationLabel
              withTag:(NSData *)tag
            withLabel:(NSString *)label
     forAccessibility:(CFTypeRef)accessibility {
  if (!privateKey || !applicationLabel)
    return NO;

  NSMutableDictionary *attrs = [NSMutableDictionary dictionary];
  attrs[(__bridge __strong id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPrivate;
  attrs[(__bridge __strong id)kSecAttrAccessible] = (__bridge id)accessibility;
  attrs[(__bridge __strong id)kSecAttrApplicationLabel] = applicationLabel;
  if (tag)
    attrs[(__bridge __strong id)kSecAttrApplicationTag] = tag;
  if (label)
    attrs[(__bridge __strong id)kSecAttrLabel] = label;

  return [self addKey:[privateKey unprotectedData] withAttributes:attrs];
}

// Actually not used, can be removed.
+ (BOOL)addPrivateKey:(SecureData *)privateKey withApplicationLabel:(NSString *)applicationLabel withTag:(NSData *)tag {
  return [self addPrivateKey:privateKey
        withApplicationLabel:applicationLabel
                     withTag:tag
                   withLabel:nil
            forAccessibility:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
}


+ (BOOL)addPublicKey:(NSData *)publickKey
          privateKey:(SecureData *)privateKey
withApplicationLabel:(NSString *)applicationLabel
             withTag:(NSData *)tag
           withLabel:(NSString *)label
withPrivateKeyAccessibility:(CFTypeRef)accessibility {
  if (!publickKey || !privateKey)
    return NO;

  if (!applicationLabel)
    applicationLabel = [publickKey stringSHA256];

  BOOL success = [self addPublicKey:publickKey
               withApplicationLabel:applicationLabel
                            withTag:tag
                          withLabel:label
                   forAccessibility:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly];
  if (!success)
    return NO;

  success = [self addPrivateKey:privateKey
           withApplicationLabel:applicationLabel
                        withTag:tag
                      withLabel:label
               forAccessibility:accessibility];
  if (!success) {
    [self deleteKeysWithApplicationLabel:applicationLabel];
    return NO;
  }
  return YES;
}

+ (BOOL)addPublicKey:(NSData *)publickKey
          privateKey:(SecureData *)privateKey
withApplicationLabel:(NSString *)applicationLabel
             withTag:(NSData *)tag
           withLabel:(NSString *)label {
  return [self addPublicKey:publickKey
                 privateKey:privateKey
       withApplicationLabel:applicationLabel
                    withTag:tag
                  withLabel:label
withPrivateKeyAccessibility:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
}


+ (BOOL)addSymmetricKey:(SecureData *)symmetricKey
   withApplicationLabel:(NSString *)applicationLabel
                withTag:(NSData *)tag
              withLabel:(NSString *)label
       forAccessibility:(CFTypeRef)accessibility {
  if (!symmetricKey || !applicationLabel)
    return NO;

  NSMutableDictionary *attrs = [NSMutableDictionary dictionary];
  attrs[(__bridge __strong id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassSymmetric;
  attrs[(__bridge __strong id)kSecAttrAccessible] = (__bridge id)accessibility;
  attrs[(__bridge __strong id)kSecAttrApplicationLabel] = applicationLabel;
  if (tag)
    attrs[(__bridge __strong id)kSecAttrApplicationTag] = tag;
  if (label)
    attrs[(__bridge __strong id)kSecAttrLabel] = label;

  return [self addKey:[symmetricKey unprotectedData] withAttributes:attrs];
}

+ (BOOL)addSymmetricKey:(SecureData *)symmetricKey
   withApplicationLabel:(NSString *)applicationLabel
                withTag:(NSData *)tag {
  return [self addSymmetricKey:symmetricKey
          withApplicationLabel:applicationLabel
                       withTag:tag
                     withLabel:nil
              forAccessibility:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
}


#pragma mark - Access key data

+ (NSData *)keyDataWithApplicationLabel:(NSString *)applicationLabel
                             attributes:(NSDictionary *)attrs {
  if (!applicationLabel || !attrs[(__bridge id)(kSecAttrKeyClass)])
    return nil;

  NSMutableDictionary *fullAttrs = [NSMutableDictionary dictionaryWithDictionary:attrs];
  fullAttrs[(__bridge __strong id)(kSecClass)] = (__bridge id)(kSecClassKey);
  fullAttrs[(__bridge __strong id)kSecAttrApplicationLabel] = applicationLabel;
  if (fullAttrs[(__bridge id)(kSecAttrIsPermanent)] == nil)
    fullAttrs[(__bridge __strong id)(kSecAttrIsPermanent)] = @(YES);
  fullAttrs[(__bridge __strong id)(kSecReturnData)] = @(YES);

  CFTypeRef keyData = nil;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)fullAttrs,
                                        &keyData);
  if (status != errSecSuccess) {
    NSLog(@"Error cannot get key with app label %@ from keychain, OSStatus == %d.",
          applicationLabel, (int)status);
    return nil;
  }

  return (__bridge_transfer NSData *)keyData;
}

+ (NSData *)publicKeyWithApplicationLabel:(NSString *)applicationLabel {
  NSDictionary *attrs = @{(__bridge __strong id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic};
  return [self keyDataWithApplicationLabel:applicationLabel attributes:attrs];
}

+ (SecureData *)privateKeyWithApplicationLabel:(NSString *)applicationLabel {
  NSDictionary *attrs = @{(__bridge __strong id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate};
  return [SecureData secureDataWithUnprotectedData:[self keyDataWithApplicationLabel:applicationLabel attributes:attrs]];
}

+ (SecureData *)symmetricKeyWithApplicationLabel:(NSString *)applicationLabel {
  NSDictionary *attrs = @{(__bridge __strong id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassSymmetric};
  return [SecureData secureDataWithUnprotectedData:[self keyDataWithApplicationLabel:applicationLabel attributes:attrs]];
}


#pragma mark - Access key attributes

+ (NSDictionary *)keyAttributesWithApplicationLabel:(NSString *)applicationLabel
                                    queryAttributes:(NSDictionary *)queryAttributes {
  if (!applicationLabel || !queryAttributes ||
      !queryAttributes[(__bridge id)(kSecAttrKeyClass)])
    return nil;

  NSMutableDictionary *fullAttrs = [NSMutableDictionary dictionaryWithDictionary:queryAttributes];
  fullAttrs[(__bridge __strong id)(kSecClass)] = (__bridge id)(kSecClassKey);
  fullAttrs[(__bridge __strong id)(kSecAttrApplicationLabel)] = applicationLabel;
  fullAttrs[(__bridge __strong id)(kSecReturnData)] = @YES;
  fullAttrs[(__bridge __strong id)(kSecReturnAttributes)] = @YES;

  CFTypeRef resultData = nil;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)fullAttrs,
                                        &resultData);
  if (status != errSecSuccess) {
    NSLog(@"Error cannot get key with app label %@ from keychain, OSStatus == %d.",
          applicationLabel, (int)status);
    return nil;
  }

  return (__bridge_transfer NSDictionary *)resultData;
}

+ (NSDictionary *)publicKeyAttributesWithApplicationLabel:(NSString *)applicationLabel {
   NSDictionary *queryAttributes = @{(__bridge __strong id)(kSecAttrKeyClass): (__bridge id)(kSecAttrKeyClassPublic)};
  return [self keyAttributesWithApplicationLabel:applicationLabel
                                 queryAttributes:queryAttributes];
}

+ (NSDictionary *)privateKeyAttributesWithApplicationLabel:(NSString *)applicationLabel {
  NSDictionary *queryAttributes = @{(__bridge __strong id)(kSecAttrKeyClass): (__bridge id)(kSecAttrKeyClassPrivate)};
  return [self keyAttributesWithApplicationLabel:applicationLabel
                                 queryAttributes:queryAttributes];
}

+ (NSDictionary *)symmetricKeyAttributesWithApplicationLabel:(NSString *)applicationLabel {
  NSDictionary *queryAttributes = @{(__bridge __strong id)(kSecAttrKeyClass): (__bridge id)(kSecAttrKeyClassSymmetric)};
  return [self keyAttributesWithApplicationLabel:applicationLabel
                                 queryAttributes:queryAttributes];
}


#pragma mark - Key updates

+ (BOOL)keyUpdateWithApplicationLabel:(NSString *)applicationLabel
                      queryAttributes:(NSDictionary *)queryAttributes
                    updatedAttributes:(NSDictionary *)updatedAttributes {
  if (!applicationLabel || !updatedAttributes || !queryAttributes ||
      !queryAttributes[(__bridge id)(kSecAttrKeyClass)])
    return NO;

  NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:queryAttributes];
  query[(__bridge __strong id)(kSecClass)] = (__bridge id)(kSecClassKey);
  query[(__bridge __strong id)kSecAttrApplicationLabel] = applicationLabel;

  NSMutableDictionary *update = [NSMutableDictionary dictionaryWithDictionary:updatedAttributes];
  // Updating kSecAttrAccessible is a particular case (see Keychain Services
  // Ref documentation).
  if (updatedAttributes[(__bridge __strong id)(kSecAttrAccessible)]) {
    NSDictionary *itemAttrs = @{(__bridge __strong id)kSecAttrKeyClass: queryAttributes[(__bridge id)(kSecAttrKeyClass)]};
    NSData *itemData = [self keyDataWithApplicationLabel:applicationLabel
                                              attributes:itemAttrs];
    if (!itemData) {
      NSLog(@"Error cannot get key value with application label %@.",
            applicationLabel);
      return NO;
    }
    update[(__bridge __strong id)(kSecValueData)] = itemData;
  }

  OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                  (__bridge CFDictionaryRef)update);
  if (status != errSecSuccess) {
    NSLog(@"Error updating key with app label %@ from keychain, OSStatus == %d.",
          applicationLabel, (int)status);
    return NO;
  }
  return YES;
}

+ (BOOL)updateSymmetricKeyAccessibility:(CFTypeRef)accessibility withApplicationLabel:(NSString *)applicationLabel {
  if (!accessibility || !applicationLabel)
    return NO;

  NSDictionary *queryAttributes = @{(__bridge __strong id)(kSecAttrKeyClass): (__bridge id)(kSecAttrKeyClassSymmetric)};
  NSDictionary *updatedAttributes = @{(__bridge __strong id)(kSecAttrAccessible): (__bridge id)(accessibility)};

  return [self keyUpdateWithApplicationLabel:applicationLabel
                             queryAttributes:queryAttributes
                           updatedAttributes:updatedAttributes];
}

+ (BOOL)updatePrivateKeyAccessibility:(CFTypeRef)accessibility withApplicationLabel:(NSString *)applicationLabel {
  if (!accessibility || !applicationLabel)
    return NO;

  NSDictionary *queryAttributes = @{(__bridge __strong id)(kSecAttrKeyClass): (__bridge id)(kSecAttrKeyClassPrivate)};
  NSDictionary *updatedAttributes = @{(__bridge __strong id)(kSecAttrAccessible): (__bridge id)(accessibility)};

  return [self keyUpdateWithApplicationLabel:applicationLabel
                             queryAttributes:queryAttributes
                           updatedAttributes:updatedAttributes];
}


#pragma mark - Access public key label

+ (NSString *)publicKeyLabelWithApplicationLabel:(NSString *)applicationLabel {
  NSDictionary *attrs = [self publicKeyAttributesWithApplicationLabel:applicationLabel];
  if (!attrs)
    return nil;

  return attrs[(__bridge id)(kSecAttrLabel)];
}

+ (BOOL)setPublicKeyLabel:(NSString *)label withApplicationLabel:(NSString *)applicationLabel {
  if (!label || !applicationLabel)
    return NO;

  NSDictionary *queryAttributes = @{(__bridge __strong id)(kSecAttrKeyClass): (__bridge id)(kSecAttrKeyClassPublic)};
  NSDictionary *updatedAttributes = @{(__bridge __strong id)(kSecAttrLabel): label};

  return [self keyUpdateWithApplicationLabel:applicationLabel
                             queryAttributes:queryAttributes
                           updatedAttributes:updatedAttributes];
}


#pragma mark - Keys from tag

+ (NSArray *)keysWithApplicationTag:(NSData *)applicationTag {
  if (!applicationTag)
    return nil;

  NSMutableDictionary *fullAttrs = [NSMutableDictionary dictionary];
  fullAttrs[(__bridge __strong id)(kSecClass)] = (__bridge id)(kSecClassKey);
  fullAttrs[(__bridge __strong id)(kSecAttrApplicationTag)] = applicationTag;
  fullAttrs[(__bridge __strong id)(kSecReturnData)] = @(YES);
  fullAttrs[(__bridge __strong id)(kSecReturnAttributes)] = @(YES);
  fullAttrs[(__bridge __strong id)(kSecMatchLimit)] = (__bridge id)(kSecMatchLimitAll);

  CFTypeRef resultData = nil;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)fullAttrs,
                                        &resultData);
  if (status != errSecSuccess) {
    NSLog(@"Error cannot get keys with app tag %@ from keychain, OSStatus == %d.",
          applicationTag, (int)status);
    return nil;
  }

  return (__bridge_transfer NSArray *)resultData;
}


#pragma mark - Delete keys

+ (BOOL)deleteKeysWithAttributes:(NSDictionary *)attrs {
  NSMutableDictionary *fullAttrs = [NSMutableDictionary dictionaryWithDictionary:attrs];
  fullAttrs[(__bridge __strong id)(kSecClass)] = (__bridge id)(kSecClassKey);

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)fullAttrs);
  if (status != errSecSuccess && status != errSecItemNotFound) {
    NSLog(@"Error removing key from keychain, OSStatus == %d.", (int)status);
    return NO;
  }
  return YES;
}

+ (BOOL)deleteKeysWithTag:(NSData *)tag {
  if (!tag)
    return NO;

  NSDictionary *queryAttrs = @{(__bridge __strong id)kSecAttrApplicationTag: tag};
  return [self deleteKeysWithAttributes:queryAttrs];
}

+ (BOOL)deleteKeysWithApplicationLabel:(NSString *)applicationLabel {
  if (!applicationLabel)
    return NO;

  NSDictionary *queryAttrs = @{(__bridge __strong id)kSecAttrApplicationLabel: applicationLabel};
  return [self deleteKeysWithAttributes:queryAttrs];
}


#pragma mark - Helpers

+ (void)deleteAll {
  NSLog(@"Deleting all items inserted in keychain");
  for (id secclass in @[
                        (__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecClassInternetPassword,
                        (__bridge id)kSecClassCertificate,
                        (__bridge id)kSecClassKey,
                        (__bridge id)kSecClassIdentity]) {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  secclass, (__bridge id)kSecClass,
                                  nil];
    SecItemDelete((__bridge CFDictionaryRef)query);
  }
}

@end
