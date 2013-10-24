//
//  FECDecoder.h
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


@interface FECDecoder : NSObject

@property (nonatomic, readonly, assign) int threshold;


// A chunk is encoded as index||threshold||fec_chunk.
// Return 0 on success, -1 on error; -2 if the share already exists in the
// FEC's context; or -3 if there are already enough chunk for decoding the
// original data.
- (NSInteger)addChunk:(NSData *)chunk;

// Return YES if it has enough chunks to attempt decoding the whole data.
- (BOOL)canDecode;

// Either return decoded data reassembled from threshold differents chunks, or
// return nil if it couldn't decode it.
- (NSData *)decode;

@end
