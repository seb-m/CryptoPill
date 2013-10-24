//
//  SecureData+HKDF.h
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;

#import "SecureData.h"


@interface SecureData (HKDF)

+ (SecureData *)hkdfForKey:(SecureData *)key info:(NSData *)info derivedKeyLength:(NSUInteger)derivedKeyLength;

@end
