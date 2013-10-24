//
//  NSData+Hex.h
//  CryptoPill
//
//  Created by Sébastien Martini on 28/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (Hex)

- (NSString *)hexadecimalEncodingFormatted;
- (NSString *)hexadecimalEncodingCompact;

@end
