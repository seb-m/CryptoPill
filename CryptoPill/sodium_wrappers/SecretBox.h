//
//  SecretBox.h
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


extern const uint64_t kScryptNDefault;
extern const uint64_t kScryptNAlternative1;
extern const uint32_t kScryptrDefault;
extern const uint32_t kScryptpDefault;


@class SecureData;

@interface SecretBox : NSObject

// Encryptions without nonces internally generate random nonces. These class
// methods return nil if an error happened. Each method has also its SecureData
// counterpart method.


+ (SecureData *)secretBoxGenerateKey;

// Encryption
+ (NSData *)secretBoxData:(NSData *)data key:(SecureData *)key nonce:(NSData *)nonce;
+ (NSData *)secretBoxSecureData:(SecureData *)data key:(SecureData *)key nonce:(NSData *)nonce;

+ (NSData *)secretBoxData:(NSData *)data key:(SecureData *)key;
+ (NSData *)secretBoxSecureData:(SecureData *)data key:(SecureData *)key;

// Use scrypt key derivation
+ (NSData *)secretBoxData:(NSData *)data password:(SecureData *)password N:(uint64_t)N r:(uint32_t)r p:(uint32_t)p;
+ (NSData *)secretBoxSecureData:(SecureData *)data password:(SecureData *)password N:(uint64_t)N r:(uint32_t)r p:(uint32_t)p;

// Decryption
+ (NSData *)secretBoxDataOpen:(NSData *)encryptedData key:(SecureData *)key;
+ (SecureData *)secretBoxSecureDataOpen:(NSData *)encryptedData key:(SecureData *)key;

// Use scrypt key derivation
+ (NSData *)secretBoxDataOpen:(NSData *)encryptedData password:(SecureData *)password;
+ (SecureData *)secretBoxSecureDataOpen:(NSData *)encryptedData password:(SecureData *)password;

// Helpers to remove / insert leading zero bytes. See NaCl documentation for more
// details.
//
// Example:
//  NSData *encryptedData = [SecretBox secretBoxRemoveZeroBytes:[SecretBox secretBoxData:plaintext
//                                                                                   key:secretKey]];
//  NSData *decryptedData = [SecretBox secretBoxDataOpen:[SecretBox secretBoxInsertZeroBytes:encryptedData]
//                                                   key:secretKey];
//
+ (NSData *)secretBoxRemoveZeroBytes:(NSData *)encryptedData;
+ (NSData *)secretBoxInsertZeroBytes:(NSData *)encryptedData;

@end
