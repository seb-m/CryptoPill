//
//  HKDFTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#include <stdint.h>
#include <stdio.h>

#include <CommonCrypto/CommonHMAC.h>

#include "hkdf.h"


struct hkdf_vector {
  CCHmacAlgorithm hmac_algorithm;
  int ikmlength;
  const char *ikmarray;
  int saltlength;
  const char *saltarray;
  int infolength;
  const char *infoarray;
  int prklength;
  const char *prkarray;
  int okmlength;
  const char *okmarray;
};


static const struct hkdf_vector hkdf_vectors[7] = {
  {   /* RFC 5869 A.1. Test Case 1 */
    kCCHmacAlgSHA256,
    22,
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    13,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
    10,
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
    32,
    "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844A"
    "D7C2B3E5",
    42,
    "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56"
    "ECC4C5BF34007208D5B887185865"
  },
  {   /* RFC 5869 A.2. Test Case 2 */
    kCCHmacAlgSHA256,
    80,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
    "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
    "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
    "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
    "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45"
    "\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
    80,
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d"
    "\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b"
    "\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
    "\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97"
    "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5"
    "\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf",
    80,
    "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd"
    "\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb"
    "\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
    "\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7"
    "\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5"
    "\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    32,
    "06A6B88C5853361A06104C9CEB35B45C"
    "EF760014904671014A193F40C15FC244",
    82,
    "B11E398DC80327A1C8E7F78C596A4934"
    "4F012EDA2D4EFAD8A050CC4C19AFA97C"
    "59045A99CAC7827271CB41C65E590E09"
    "DA3275600C2F09B8367793A9ACA3DB71"
    "CC30C58179EC3E87C14C01D5C1F3434F"
    "1D87"
  },
  {   /* RFC 5869 A.3. Test Case 3 */
    kCCHmacAlgSHA256,
    22,
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    0,
    "",
    0,
    "",
    32,
    "19EF24A32C717B167F33A91D6F648BDF"
    "96596776AFDB6377AC434C1C293CCB04",
    42,
    "8DA4E775A563C18F715F802A063C5A31"
    "B8A11F5C5EE1879EC3454E5F3C738D2D"
    "9D201395FAA4B61A96C8"
  },
  {   /* RFC 5869 A.4. Test Case 4 */
    kCCHmacAlgSHA1,
    11,
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    13,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
    10,
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
    20,
    "9B6C18C432A7BF8F0E71C8EB88F4B30BAA2BA243",
    42,
    "085A01EA1B10F36933068B56EFA5AD81"
    "A4F14B822F5B091568A9CDD4F155FDA2"
    "C22E422478D305F3F896"
  },
  {   /* RFC 5869 A.5. Test Case 5 */
    kCCHmacAlgSHA1,
    80,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
    "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
    "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
    "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
    "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45"
    "\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
    80,
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D"
    "\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B"
    "\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
    "\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97"
    "\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5"
    "\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF",
    80,
    "\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD"
    "\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB"
    "\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9"
    "\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7"
    "\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5"
    "\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
    20,
    "8ADAE09A2A307059478D309B26C4115A224CFAF6",
    82,
    "0BD770A74D1160F7C9F12CD5912A06EB"
    "FF6ADCAE899D92191FE4305673BA2FFE"
    "8FA3F1A4E5AD79F3F334B3B202B2173C"
    "486EA37CE3D397ED034C7F9DFEB15C5E"
    "927336D0441F4C4300E2CFF0D0900B52"
    "D3B4"
  },
  {   /* RFC 5869 A.6. Test Case 6 */
    kCCHmacAlgSHA1,
    22,
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    0,
    "",
    0,
    "",
    20,
    "DA8C8A73C7FA77288EC6F5E7C297786AA0D32D01",
    42,
    "0AC1AF7002B3D761D1E55298DA9D0506"
    "B9AE52057220A306E07B6B87E8DF21D0"
    "EA00033DE03984D34918"
  },
  {   /* RFC 5869 A.7. Test Case 7. */
    kCCHmacAlgSHA1,
    22,
    "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
    "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
    0,
    0,
    0,
    "",
    20,
    "2ADCCADA18779E7C2077AD2EB19D3F3E731385DD",
    42,
    "2C91117204D745F3500D636A62F64F0A"
    "B3BAE548AA53D423B0D1F27EBBA6F5E5"
    "673A081D70CCE7ACFC48"
  }
};

/*
 * Check the hash value against the expected string, expressed in hex
 */
static const char hexdigits[ ] = "0123456789ABCDEF";

static int check_match(const uint8_t *hashvalue,
                       const char *hexstr, int hashsize) {
  int i;

  for (i = 0; i < hashsize; ++i) {
    if (*hexstr++ != hexdigits[(hashvalue[i] >> 4) & 0xF])
      return 0;
    if (*hexstr++ != hexdigits[hashvalue[i] & 0xF])
      return 0;
  }
  return 1;
}


@interface HKDFTests : SenTestCase

@end

@implementation HKDFTests

- (void)setUp {
  [super setUp];
  // Set-up code here.
}

- (void)tearDown {
  // Tear-down code here.
  [super tearDown];
}

- (void)testReference {
  uint8_t okm[128];
  int ret;
  int i;

  for (i = 0; i < 7; ++i) {
    ret = hkdf(hkdf_vectors[i].hmac_algorithm,
               (const uint8_t *)hkdf_vectors[i].saltarray,
               hkdf_vectors[i].saltlength,
               (const uint8_t *)hkdf_vectors[i].ikmarray,
               hkdf_vectors[i].ikmlength,
               (const uint8_t *)hkdf_vectors[i].infoarray,
               hkdf_vectors[i].infolength,
               okm,
               hkdf_vectors[i].okmlength);
    STAssertFalse(ret == -1, @"call to hkdf() failed");

    ret = check_match(okm, hkdf_vectors[i].okmarray,
                      hkdf_vectors[i].okmlength);
    STAssertFalse(ret == 0, @"result value doesn't match reference value");
  }
}

@end
