//
//  NSArray+Concat.h
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


@interface NSArray (Concat)

// Mainly used for 'info' data string in crypto operations.
// Supports only arrays compounded of NSString (UTF8), NSData and NSNumber
// elements. Return the concatenated data string; or nil if one element had not
// an appropriate tyme.
- (NSData *)concatToData;

@end
