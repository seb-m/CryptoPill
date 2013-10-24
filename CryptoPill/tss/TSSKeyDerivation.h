//
//  TSSKeyDerivation.h
//  CryptoPill
//
//  Created by Sébastien Martini on 07/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


@class SecureData;

@interface TSSKeyDerivation : NSObject

// Return a 32 bytes Curve25519 secret key obtained fron:
// HKDF(sha256, salt=NULL, share_at_index, "share_public_key" || id || index, 32)
+ (SecureData *)secretKeyForShare:(SecureData *)share;

// Return shareSecretKeyAtIndex . P (over Ed25519).
// Note: the returned result is over Ed25519 not over Curve25519 because the
// main use of this derived key will be through the Schnorr protocol and this
// protocol needs to accomplish multi-scalar computations therefore needs the
// y coordinate which the Montgomery curve doesn't provide. So the returned
// point of this method is differently encoded than what it would be with
// Curve25519, but if this point needed to be used later on Curve25519
// computations then it exists a method to convert it appropriately, see the
// class EdMontConv.
+ (NSData *)publicKeyForShare:(SecureData *)share;

// Check that the given share corresponds to publicKey.
+ (BOOL)checkShare:(SecureData *)share withPublicKey:(NSData *)publicKey;

@end
