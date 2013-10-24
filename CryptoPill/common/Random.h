//
//  Random.h
//  CryptoPill
//
//  Created by Sébastien Martini on 07/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;

#include <stdlib.h>


@class SecureData;

@interface Random : NSObject

// These methods return nil if they fail.
+ (NSData *)randomData:(size_t)len;

+ (SecureData *)randomSecureData:(size_t)len;

@end
