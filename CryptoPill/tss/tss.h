#ifndef CRYPTO_TSS_H_
#define CRYPTO_TSS_H_

#include <stdint.h>


#define TSS_IDENTIFIER_SIZE 16


typedef enum {
  TSS_NONE,
  TSS_SHA1,
  TSS_SHA256,
  TSS_END
} tss_hash;

typedef struct {
  uint8_t identifier[TSS_IDENTIFIER_SIZE];
  tss_hash hash;
  uint8_t threshold;
  uint8_t index;
  uint8_t coefs_poly[256];
  uint8_t *secret;
  uint16_t secret_len;
  uint8_t *shares[256];
} tss_ctx;


// Secret sharing operations.

// Return 0 on success, -1 on error.
int tss_share_init(tss_ctx *ctx, const uint8_t identifier[TSS_IDENTIFIER_SIZE],
                   uint8_t threshold, tss_hash hash_algorithm,
                   const uint8_t *secret, uint16_t secret_len);

// Return the expected size in bytes of a share.
uint32_t tss_share_size(const tss_ctx *ctx);

// Return 0 on success if a new share was generated, -1 on error; or -2 if no
// more share couldn't be generated for this context. share must provide
// tss_share_size() allocated bytes. It is usually a bad idea to mix calls to
// this function with calls to tss_share() as indexes can overlap. Internally
// this function is just maintaining and incrementing an index value and
// repeatedly calling tss_share() with this index.
int tss_share_next(tss_ctx *ctx, uint8_t *share);

// Return 0 on success, -1 on error. Index is the index of the share to return
// and must be an integer between [1, 254]. share must provide tss_share_size()
// allocated bytes.
int tss_share(tss_ctx *ctx, uint8_t index, uint8_t *share);


// Secret recovering operations.

// Return 0 on success, -1 on error.
int tss_recover_init(tss_ctx *ctx);

// On success return the index (number > 0) of the share that was just added.
// Return -1 on error, -2 if a share for the same index is already inserted in
// the context, -3 if the share is invalid (bad format).
int tss_recover_add(tss_ctx *ctx, const uint8_t *share);

// Return the size in bytes of the secret (not including the hash of the secret
// value).
uint16_t tss_recover_secret_size(const tss_ctx *ctx);

// Return the threshold's value, 0 if still undefined (at least one share
// must have been decoded in order for the threshold value to be available).
// This number represents the number of shares needed before the secret's value
// can be recovered by tss_recover().
uint8_t tss_recover_threshold(const tss_ctx *ctx);

// Return the number of shares currently inserted in ctx.
uint8_t tss_recover_num_shares(const tss_ctx *ctx);

// Return 0 on success if secret was successfully recovered, -1 on error,
// -2 if there are still not enough shares available in the context to
// recover the secret value, -3 if the hash value comparison of the secret
// failed. secret must provide tss_recover_secret_size() allocated bytes.
int tss_recover(tss_ctx *ctx, uint8_t *secret);

// Return 0 on success if polynomial coefficients were succeffully recovered,
// -1 on error, -2 if there are still not enough shares available.
int tss_recover_coefficients(tss_ctx *ctx);

// Common function to both contexts initialized via tss_share_init and
// tss_recover_init.
void tss_free(tss_ctx *ctx);

#endif  // CRYPTO_TSS_H_
