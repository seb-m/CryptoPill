//
//  NSArray+HMAC.h
//  CryptoPill
//
//  Created by Sébastien Martini on 18/07/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <Foundation/Foundation.h>


@class SecureData;

@interface NSArray (HMAC)

- (NSData *)hmacSha256WithKey:(SecureData *)key;

@end
