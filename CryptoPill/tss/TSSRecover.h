//
//  TSSRecover.h
//  CryptoPill
//
//  Created by Sébastien Martini on 05/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


@class SecureData;

@interface TSSRecover : NSObject

// Return 0 on success, -1 on error; or -2 if the share already exists in the
// TSS's context.
- (NSInteger)addShare:(SecureData *)share;

// Secret's identifier, must be called after at least one call to -addShare was
// made and succeeded. Return nil if unavailable.
- (NSData *)identifier;

// 0 if undefined, a value < 255 otherwise. must be called after at least one
// call to -addShare was made and succeeded.
- (NSUInteger)threshold;

// YES if it has enough share to attempt recovering the secret data.
- (BOOL)canRecover;
- (NSUInteger)numberOfSharesNeededForRecovering;

// Return nil if it failed.
- (SecureData *)recover;

@end
