//
//  KeychainTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 14/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "Curve25519.h"
#import "Keychain.h"
#import "SecretBox.h"
#import "SecureData.h"


@interface KeychainTests : SenTestCase

@end

@implementation KeychainTests

- (void)testPublicKey {
  BOOL success;
  NSString *appLabel = @"testPublicKey";
  SecureData *privateKey = [Curve25519 scalarmultCurve25519GenerateScalar];
  NSData *publicKey = [Curve25519 scalarmultCurve25519BaseWithScalar:privateKey];

  success = [Keychain addPublicKey:publicKey
              withApplicationLabel:appLabel
                           withTag:nil
                         withLabel:nil
                  forAccessibility:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
  STAssertTrue(success, nil);
  NSData *publicKeyKeychain = [Keychain publicKeyWithApplicationLabel:appLabel];
  STAssertTrue([publicKey isEqualToData:publicKeyKeychain], nil);
  success = [Keychain deleteKeysWithApplicationLabel:appLabel];
  STAssertTrue(success, nil);
  publicKeyKeychain = [Keychain publicKeyWithApplicationLabel:appLabel];
  STAssertTrue(publicKeyKeychain == nil, nil);
}

- (void)testPrivateKey {
  BOOL success;
  NSString *appLabel = @"testPrivateKey";
  SecureData *privateKey = [Curve25519 scalarmultCurve25519GenerateScalar];

  success = [Keychain addPrivateKey:privateKey
               withApplicationLabel:appLabel
                            withTag:nil
                          withLabel:nil
                   forAccessibility:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
  STAssertTrue(success, nil);
  SecureData *privateKeyKeychain = [Keychain privateKeyWithApplicationLabel:appLabel];
  STAssertTrue([privateKey isEqualToSecureData:privateKeyKeychain], nil);
  success = [Keychain deleteKeysWithApplicationLabel:appLabel];
  STAssertTrue(success, nil);
  privateKeyKeychain = [Keychain privateKeyWithApplicationLabel:appLabel];
  STAssertTrue(privateKeyKeychain == nil, nil);
}

- (void)testKeypair {
  BOOL success;
  NSString *appLabel = @"testKeypair";
  SecureData *privateKey = [Curve25519 scalarmultCurve25519GenerateScalar];
  NSData *publicKey = [Curve25519 scalarmultCurve25519BaseWithScalar:privateKey];

  success = [Keychain addPublicKey:publicKey
                        privateKey:privateKey
              withApplicationLabel:appLabel
                           withTag:nil
                         withLabel:nil];
  STAssertTrue(success, nil);
  SecureData *privateKeyKeychain = [Keychain privateKeyWithApplicationLabel:appLabel];
  STAssertTrue([privateKey isEqualToSecureData:privateKeyKeychain], nil);
  NSData *publicKeyKeychain = [Keychain publicKeyWithApplicationLabel:appLabel];
  STAssertTrue([publicKey isEqualToData:publicKeyKeychain], nil);
  success = [Keychain deleteKeysWithApplicationLabel:appLabel];
  STAssertTrue(success, nil);
  privateKeyKeychain = [Keychain privateKeyWithApplicationLabel:appLabel];
  STAssertTrue(privateKeyKeychain == nil, nil);
  publicKeyKeychain = [Keychain publicKeyWithApplicationLabel:appLabel];
  STAssertTrue(publicKeyKeychain == nil, nil);
}

- (void)testSymmetricKey {
  BOOL success;
  NSString *appLabel = @"testSymmetricKey";
  SecureData *symmetricKey = [SecretBox secretBoxGenerateKey];

  success = [Keychain addSymmetricKey:symmetricKey withApplicationLabel:appLabel withTag:nil];
  STAssertTrue(success, nil);
  SecureData *symmetricKeyKeychain = [Keychain symmetricKeyWithApplicationLabel:appLabel];
  STAssertTrue([symmetricKey isEqualToSecureData:symmetricKeyKeychain], nil);
  success = [Keychain deleteKeysWithApplicationLabel:appLabel];
  STAssertTrue(success, nil);
  symmetricKeyKeychain = [Keychain symmetricKeyWithApplicationLabel:appLabel];
  STAssertTrue(symmetricKeyKeychain == nil, nil);
}

- (void)testGroupKeys {
  BOOL success;
  NSData *appTag = [@"testGroupKeys" dataUsingEncoding:NSUTF8StringEncoding];

  NSString *publicKey1Label = @"publicKey1Label";
  NSData *publicKey1Key = [@"publicKey1Key" dataUsingEncoding:NSUTF8StringEncoding];
  success = [Keychain addPublicKey:publicKey1Key withApplicationLabel:publicKey1Label withTag:appTag withLabel:publicKey1Label forAccessibility:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly];
  STAssertTrue(success, nil);

  NSString *publicKey2Label = @"publicKey2Label";
  NSData *publicKey2Key = [@"publicKey2Key" dataUsingEncoding:NSUTF8StringEncoding];
  success = [Keychain addPublicKey:publicKey2Key withApplicationLabel:publicKey2Label withTag:appTag withLabel:publicKey2Label forAccessibility:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly];
  STAssertTrue(success, nil);

  NSString *publicKey3Label = @"publicKey3Label";
  NSData *publicKey3Key = [@"publicKey3Key" dataUsingEncoding:NSUTF8StringEncoding];
  success = [Keychain addPublicKey:publicKey3Key withApplicationLabel:publicKey3Label withTag:appTag withLabel:publicKey3Label forAccessibility:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly];
  STAssertTrue(success, nil);

  NSString *publicKey4Label = @"publicKey4Label";
  NSData *publicKey4Key = [@"publicKey4Key" dataUsingEncoding:NSUTF8StringEncoding];
  success = [Keychain addPublicKey:publicKey4Key withApplicationLabel:publicKey4Label withTag:appTag withLabel:publicKey4Label forAccessibility:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly];
  STAssertTrue(success, nil);

  NSArray *keys = [Keychain keysWithApplicationTag:appTag];
  STAssertTrue([keys count] == 4, nil);

  NSDictionary *key = [Keychain publicKeyAttributesWithApplicationLabel:publicKey1Label];
  STAssertTrue(key != nil && [[key objectForKey:(__bridge id)(kSecAttrLabel)] isEqualToString:publicKey1Label], nil);

  success = [Keychain deleteKeysWithApplicationLabel:publicKey1Label];
  STAssertTrue(success, nil);
  keys = [Keychain keysWithApplicationTag:appTag];
  STAssertTrue([keys count] == 3, nil);

  key = [Keychain publicKeyAttributesWithApplicationLabel:publicKey1Label];
  STAssertTrue(key == nil, nil);

  success = [Keychain setPublicKeyLabel:@"foobar" withApplicationLabel:publicKey2Label];
  STAssertTrue(success, nil);
  key = [Keychain publicKeyAttributesWithApplicationLabel:publicKey2Label];
  STAssertTrue(key != nil && [[key objectForKey:(__bridge id)(kSecAttrLabel)] isEqualToString:@"foobar"], nil);

  NSString *label = [Keychain publicKeyLabelWithApplicationLabel:publicKey2Label];
  STAssertTrue(label != nil && [label isEqualToString:@"foobar"], nil);

  success = [Keychain setPublicKeyLabel:@"foobar" withApplicationLabel:publicKey1Label];
  STAssertTrue(!success, nil);

  success = [Keychain deleteKeysWithTag:appTag];
  STAssertTrue(success, nil);

  keys = [Keychain keysWithApplicationTag:appTag];
  STAssertTrue([keys count] == 0, nil);
}

@end
