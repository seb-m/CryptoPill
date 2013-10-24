//
//  Keychain.h
//  CryptoPill
//
//  Created by Sébastien Martini on 16/08/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <Foundation/Foundation.h>


@class SecureData;

// Usage:
//
// label: user assigned
// application label: unique label (usually a hash of the public key or an
//                    unique identifier of a symmetric key) for a key pair
//                    (asymetric case) or for a symmétric key
// application tag: unique tag for a group of keys (for instance all public keys
//                  from peers)
// accessibility: by default unless all accessibility flags for newly created
//                public keys is kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//                and for private keys and symmetric keys is
//                kSecAttrAccessibleWhenUnlockedThisDeviceOnly

@interface Keychain : NSObject

// Add keys

// applicationLabel, tag and label are optionals. If not provided applicationLabel
// is assigned with the hash value of the public key.
+ (BOOL)addPublicKey:(NSData *)publickKey
withApplicationLabel:(NSString *)applicationLabel
             withTag:(NSData *)tag
           withLabel:(NSString *)label
    forAccessibility:(CFTypeRef)accessibility;

// applicationLabel must be unique. tag and label are optionals.
+ (BOOL)addPrivateKey:(SecureData *)privateKey
 withApplicationLabel:(NSString *)applicationLabel
              withTag:(NSData *)tag
            withLabel:(NSString *)label
     forAccessibility:(CFTypeRef)accessibility;

// applicationLabel, tag and label are optionals. If not provided applicationLabel
// is assigned with the hash value of the public key.
+ (BOOL)addPublicKey:(NSData *)publickKey
          privateKey:(SecureData *)privateKey
withApplicationLabel:(NSString *)applicationLabel
             withTag:(NSData *)tag
           withLabel:(NSString *)label;

+ (BOOL)addPublicKey:(NSData *)publickKey
          privateKey:(SecureData *)privateKey
withApplicationLabel:(NSString *)applicationLabel
             withTag:(NSData *)tag
           withLabel:(NSString *)label
withPrivateKeyAccessibility:(CFTypeRef)accessibility;

// applicationLabel must be unique. tag and label are optionals.
+ (BOOL)addSymmetricKey:(SecureData *)symmetricKey
   withApplicationLabel:(NSString *)applicationLabel
                withTag:(NSData *)tag
              withLabel:(NSString *)label
       forAccessibility:(CFTypeRef)accessibility;

// Shortcut for the previous method.
+ (BOOL)addSymmetricKey:(SecureData *)symmetricKey
   withApplicationLabel:(NSString *)applicationLabel
                withTag:(NSData *)tag;


// Get key data
+ (NSData *)publicKeyWithApplicationLabel:(NSString *)applicationLabel;
+ (SecureData *)privateKeyWithApplicationLabel:(NSString *)applicationLabel;
+ (SecureData *)symmetricKeyWithApplicationLabel:(NSString *)applicationLabel;


// Get key attributes
+ (NSDictionary *)publicKeyAttributesWithApplicationLabel:(NSString *)applicationLabel;
+ (NSDictionary *)privateKeyAttributesWithApplicationLabel:(NSString *)applicationLabel;
+ (NSDictionary *)symmetricKeyAttributesWithApplicationLabel:(NSString *)applicationLabel;


// Update key accessibility
+ (BOOL)updateSymmetricKeyAccessibility:(CFTypeRef)accessibility withApplicationLabel:(NSString *)applicationLabel;
+ (BOOL)updatePrivateKeyAccessibility:(CFTypeRef)accessibility withApplicationLabel:(NSString *)applicationLabel;


// Get/set public key label
+ (NSString *)publicKeyLabelWithApplicationLabel:(NSString *)applicationLabel;
+ (BOOL)setPublicKeyLabel:(NSString *)label withApplicationLabel:(NSString *)applicationLabel;


// All keys from a given tag
+ (NSArray *)keysWithApplicationTag:(NSData *)applicationTag;

// Delete keys
+ (BOOL)deleteKeysWithTag:(NSData *)tag;
+ (BOOL)deleteKeysWithApplicationLabel:(NSString *)applicationLabel;

// Helpers
+ (void)deleteAll;

@end
