//
//  FECWrapperTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 09/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#import "FECEncoder.h"
#import "FECDecoder.h"


@interface FECWrapperTests : SenTestCase

@end

@implementation FECWrapperTests

- (void)testBasic1 {
  NSInteger ret;
  NSString *lorem = @"Donec sollicitudin enim nibh, eget venenatis velit laoreet nec. Nulla porta sagittis lorem eget rhoncus. Aenean interdum justo vitae tortor sagittis lacinia. Donec sit amet erat sodales, gravida mauris ut, varius nulla. Duis vehicula lectus ut mauris tristique, vitae ultricies odio dignissim. In sit amet odio ac quam hendrerit tincidunt eget ac lacus. Integer volutpat ligula sit amet dapibus tempus. Sed eu nisi consequat eros laoreet hendrerit id ac turpis. Nulla mollis, urna et blandit facilisis, arcu orci scelerisque metus, quis ultrices nulla elit nec nisi. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vivamus congue sem quis massa porta, non vestibulum enim ullamcorper. Fusce eget quam accumsan, adipiscing nulla ac, consequat lacus. Duis molestie massa quis urna porta, quis tincidunt nibh dictum. Nam id feugiat lorem. Integer molestie iaculis viverra. Nullam tempor mi id rutrum ullamcorper. Proin vehicula ipsum sit amet leo lacinia, vitae egestas tellus imperdiet. Pellentesque adipiscing tortor nec felis iaculis eleifend at non velit. Donec dictum, nibh in pellentesque adipiscing, risus leo porta purus, ac rutrum arcu sapien ut risus. Phasellus et lectus elit. Vestibulum consectetur eu urna non adipiscing. Ut lacus lectus, aliquam id arcu blandit, mattis porttitor tellus. Donec ultrices ipsum vitae odio tincidunt rutrum. Sed porta, libero et porta tincidunt, sem nibh venenatis purus, vel blandit nunc lorem nec nulla. Nam interdum eleifend ligula vitae vehicula. Phasellus varius pellentesque lobortis. Maecenas lobortis lectus vel magna lobortis condimentum. In vitae rhoncus nisl, eu rutrum tortor. Duis pretium eleifend mauris, vel semper diam volutpat non. Fusce congue tortor metus, tristique tempus nunc euismod id. Vestibulum fringilla eget augue eu posuere. Integer vel tempus tortor, id convallis lectus. Nam sit amet ante vel velit adipiscing ullamcorper volutpat aliquet elit. Vivamus in augue ac lacus dictum scelerisque. Mauris pharetra enim at sagittis adipiscing. Etiam ac lorem condimentum, dictum odio id, dignissim erat. Fusce non tellus sed quam posuere pellentesque id et quam. Duis porttitor, metus at commodo elementum, sem mauris placerat orci, sed auctor libero quam sed tortor. Sed lobortis, mi at rutrum facilisis, massa est iaculis est, et gravida purus ligula vitae nunc. Vivamus bibendum dolor et mi faucibus, non dapibus leo cursus.";
  NSData *data = [lorem dataUsingEncoding:NSUTF8StringEncoding];

  FECEncoder *encoder = [[FECEncoder alloc] initWithData:data threshold:3];
  NSData *chunk0 = [encoder chunkAtIndex:0];
  NSData *chunk1 = [encoder chunkAtIndex:1];
  NSData *chunk2 = [encoder chunkAtIndex:2];
  NSData *chunk3 = [encoder chunkAtIndex:3];
  STAssertTrue(encoder != nil && chunk0 != nil && chunk1 != nil &&
               chunk2 != nil && chunk3 != nil, nil);

  FECDecoder *decoder = [FECDecoder new];
  ret = [decoder addChunk:chunk0];
  STAssertTrue(ret == 0, nil);
  STAssertFalse([decoder canDecode], nil);
  ret = [decoder addChunk:chunk0];
  STAssertTrue(ret == -2, nil);
  ret = [decoder addChunk:chunk1];
  STAssertTrue(ret == 0, nil);
  STAssertFalse([decoder canDecode], nil);
  ret = [decoder addChunk:chunk2];
  STAssertTrue(ret == 0, nil);
  STAssertTrue([decoder canDecode], nil);
  ret = [decoder addChunk:chunk3];
  STAssertTrue(ret == -3, nil);

  NSData *decodedData = [decoder decode];
  STAssertTrue([decodedData isEqualToData:data], nil);
}

- (void)testBasic2 {
  NSInteger ret;
  NSData *data = [@"This is a short sample of data with not many characters, that's just for testing." dataUsingEncoding:NSUTF8StringEncoding];

  FECEncoder *encoder = [[FECEncoder alloc] initWithData:data threshold:2];
  NSData *chunk1 = [encoder chunkAtIndex:1];
  NSData *chunk5 = [encoder chunkAtIndex:5];
  STAssertTrue(encoder != nil && chunk1 != nil && chunk5 != nil, nil);

  FECDecoder *decoder = [FECDecoder new];
  ret = [decoder addChunk:chunk5];
  STAssertTrue(ret == 0, nil);
  STAssertFalse([decoder canDecode], nil);
  ret = [decoder addChunk:chunk1];
  STAssertTrue(ret == 0, nil);
  STAssertTrue([decoder canDecode], nil);

  NSData *decodedData = [decoder decode];
  STAssertTrue([decodedData isEqualToData:data], nil);
}

- (void)testBasic3 {
  NSInteger ret;
  NSData *data = [@"This is a short sample of data with not many characters, that's just for testing." dataUsingEncoding:NSUTF8StringEncoding];

  FECEncoder *encoder = [[FECEncoder alloc] initWithData:data threshold:2];
  NSData *chunk1 = [encoder chunkAtIndex:1];
  NSData *chunk2 = [encoder chunkAtIndex:2];
  STAssertTrue(encoder != nil && chunk1 != nil && chunk2 != nil, nil);

  FECDecoder *decoder = [FECDecoder new];
  ret = [decoder addChunk:chunk1];
  STAssertTrue(ret == 0, nil);
  ret = [decoder addChunk:chunk2];
  STAssertTrue(ret == 0, nil);
  STAssertTrue([decoder canDecode], nil);

  NSData *decodedData = [decoder decode];
  STAssertTrue([decodedData isEqualToData:data], nil);
}

@end
