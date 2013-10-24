//
//  FECEncoder.h
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


@interface FECEncoder : NSObject

// |data| must be < 2^32 and threshold in range [0, 254].
- (id)initWithData:(NSData *)data threshold:(NSInteger)threshold;

// A returned chunk is encoded as index||threshold||fec_chunk.
- (NSData *)chunkAtIndex:(NSInteger)index;

// If this method is used it will probably a bad idea to mix its calls with
// -chunkAtIndex: as they could return the same index multiple times.
// Return nil if -hasNextChunk returns NO or if there is an error.
- (NSData *)nextChunk;

// If YES -nextChunk may return a new chunk.
- (BOOL)hasNextChunk;

@end
