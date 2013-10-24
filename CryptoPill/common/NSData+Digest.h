//
//  NSData+Digest.h
//  CryptoPill
//
//  Created by Sébastien Martini on 24/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (Digest)

- (NSData *)sha256;
- (NSString *)stringSHA256;

@end
