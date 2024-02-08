#ifndef HEADER_stl_s1_h
#define HEADER_stl_s1_h

/* stl_s1.h provides APIs for STL in suite S1 mode.

   Suite S1 features 128-bit level security (as of 2023-Dec).
   It uses the following cryptographic algorithms:

   ... TODO ... */

#include "stl_proto.h"
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_shorthash_siphash24.h>

struct stl_s1_server {
  /* identity is a compound structure of the identity private and
     public key */
  uint8_t identity[ crypto_sign_ed25519_SECRETKEYBYTES ];

  /* kex_{private,public} is the ephemeral key pair used for
     symmetric key exchange. */
  uint8_t kex_private[ crypto_scalarmult_curve25519_SCALARBYTES ];
  uint8_t kex_public [ crypto_scalarmult_curve25519_BYTES       ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uint8_t cookie_secret[ crypto_shorthash_siphash24_KEYBYTES ];
};

typedef struct stl_s1_server stl_s1_server_t;

STL_PROTOTYPES_BEGIN

uint64_t
stl_s1_server_handshake( stl_s1_server_t *     server,
                         stl_net_ctx_t const * ctx,
                         uint8_t const *       in,
                         uint64_t              in_sz,
                         uint8_t               out[ static STL_MTU ] );

STL_PROTOTYPES_END

#endif /* HEADER_stl_s1_h */
