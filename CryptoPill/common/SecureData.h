//
//  SecureData.h
//  CryptoPill
//
//  Created by Sébastien Martini on 11/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


@interface SecureData : NSObject<NSSecureCoding, NSCopying>

@property (nonatomic, readonly, assign) NSUInteger length;

+ (instancetype)secureDataWithBytes:(const void *)bytes length:(NSUInteger)length;
+ (instancetype)secureDataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length;
+ (instancetype)secureDataWithLength:(NSUInteger)length;
+ (instancetype)secureDataWithSecureData:(SecureData *)secureData;

- (const void *)bytes;
- (void *)mutableBytes;

// Copy data to self at specified index.
- (void)copySecureData:(SecureData *)data atIndex:(NSUInteger)index;

// /!\ Non constant-time
- (BOOL)isEqualToSecureData:(SecureData *)data;

// FIXME: these methods manipulate unprotected memory buffers. Likewise for
//        NSCoding methods.
+ (instancetype)secureDataWithUnprotectedData:(NSData *)data;
- (NSData *)unprotectedData;
- (void)copyUnprotectedData:(NSData *)data atIndex:(NSUInteger)index;

@end
