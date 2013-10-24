//
//  SodiumWrappersTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 09/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "Box.h"
#import "Curve25519.h"
#import "SchnorrKeypair.h"
#import "SecretBox.h"
#import "SecureData.h"


@interface SodiumWrappersTests : SenTestCase

@end

@implementation SodiumWrappersTests

- (void)testCurve25519 {
  SecureData *skInitiator = [Curve25519 scalarmultCurve25519GenerateScalar];
  NSData *pkInitiator = [Curve25519 scalarmultCurve25519BaseWithScalar:skInitiator];
  SecureData *skReceiver = [Curve25519 scalarmultCurve25519GenerateScalar];
  NSData *pkReceiver = [Curve25519 scalarmultCurve25519BaseWithScalar:skReceiver];
  SecureData *shareKey1 = [Curve25519 scalarmultCurve25519WithScalar:skInitiator publicKey:pkReceiver];
  SecureData *shareKey2 = [Curve25519 scalarmultCurve25519WithScalar:skReceiver publicKey:pkInitiator];
  STAssertTrue([shareKey1 isEqualToSecureData:shareKey2], nil);
}

- (void)testBox {
  NSData *secretData = [@"This is a big important secret we need to keep secret and only share between us." dataUsingEncoding:NSUTF8StringEncoding];
  SecureData *skInitiator = [Curve25519 scalarmultCurve25519GenerateScalar];
  NSData *pkInitiator = [Curve25519 scalarmultCurve25519BaseWithScalar:skInitiator];
  SecureData *skReceiver = [Curve25519 scalarmultCurve25519GenerateScalar];
  NSData *pkReceiver = [Curve25519 scalarmultCurve25519BaseWithScalar:skReceiver];

  NSData *encryptedData = [Box boxData:secretData publicKey:pkReceiver secretKey:skInitiator];
  STAssertTrue(encryptedData != nil, nil);
  NSData *decryptedData = [Box boxDataOpen:encryptedData publicKey:pkInitiator secretKey:skReceiver];
  STAssertTrue(decryptedData != nil, nil);
  STAssertTrue([decryptedData isEqualToData:secretData], @"decrypted secret not equal to original secret");
}

- (void)testSecretBox {
  NSData *secretData = [@"This is a big important secret we need to keep secret and only share between us." dataUsingEncoding:NSUTF8StringEncoding];
  SecureData *key = [SecretBox secretBoxGenerateKey];
  STAssertTrue(key != nil, nil);
  NSData *encryptedData = [SecretBox secretBoxData:secretData key:key];
  STAssertTrue(encryptedData != nil, nil);
  NSData *decryptedData = [SecretBox secretBoxDataOpen:encryptedData key:key];
  STAssertTrue(decryptedData != nil, nil);
  STAssertTrue([decryptedData isEqualToData:secretData], @"decrypted secret not equal to original secret");
}

- (void)testEd25519ToCurve25519Conv {
  for (int i = 0; i < 100; ++i) {
    SecureData *sk = [SchnorrKeypair generateSecretKey];
    STAssertTrue(sk != nil, nil);
    
    NSData *pk_ed = [SchnorrKeypair publicKeyFromSecretKey:sk];
    STAssertTrue(pk_ed != nil, nil);
    
    NSData *pk_mont = [Curve25519 scalarmultCurve25519BaseWithScalar:sk];
    STAssertTrue(pk_mont != nil, nil);
    
    NSData *pk_ed_conv = [Curve25519 publicKeyFromEd25519PublicKey:pk_ed];
    STAssertTrue(pk_ed_conv != nil, nil);
    
    BOOL success = [pk_mont isEqualToData:pk_ed_conv];
    STAssertTrue(success, nil);
  }
}

@end
