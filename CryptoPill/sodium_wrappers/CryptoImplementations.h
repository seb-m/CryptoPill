//
//  CryptoImplementations.h
//  CryptoPill
//
//  Created by Sébastien Martini on 06/08/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface CryptoImplementations : NSObject

// Select default libsodium crypto primitives.
+ (BOOL)selectCryptoImplementations;

@end
