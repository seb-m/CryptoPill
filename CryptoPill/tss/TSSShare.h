//
//  TSSShare.h
//  CryptoPill
//
//  Created by Sébastien Martini on 05/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


extern const NSUInteger kTSSIdentifierSize;


@class SecureData;

@interface TSSShare : NSObject

@property (nonatomic, readonly, strong) NSData *identifier;
@property (nonatomic, readonly, assign) NSUInteger threshold;


// identifier is randomly generated (16 bytes).
- (id)initWithSecret:(SecureData *)secret threshold:(NSUInteger)threshold identifier:(NSData *)identifier;
- (id)initWithSecret:(SecureData *)secret threshold:(NSUInteger)threshold;

// Valid index range: [1, 254]
- (SecureData *)shareAtIndex:(NSUInteger)index;

// If this method is used it will probably a bad idea to mix its calls with
// -shareAtIndex: as they could return multiple times the same index.
// Return nil if -hasNextShare returns NO or if there is an error.
- (SecureData *)nextShare;

// If YES -nextShare may return a new share.
- (BOOL)hasNextShare;

@end
