#ifndef HEADER_stl_s0_server_h
#define HEADER_stl_s0_server_h

/* stl_s0.h provides APIs for STL in suite S0 mode (unencrypted). */

#include "stl_base.h"
#include "stl_proto.h"
#include <stdbool.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_shorthash_siphash24.h>

struct stl_s0_server_params {

  /* identity is a compound structure of the identity private and
     public key */
  uint8_t identity[ crypto_sign_ed25519_SECRETKEYBYTES ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uint8_t cookie_secret[ crypto_shorthash_siphash24_KEYBYTES ];

  uint8_t token[16];

};

typedef struct stl_s0_server_params stl_s0_server_params_t;

struct stl_s0_server_hs {
  uint8_t identity[ crypto_sign_ed25519_PUBLICKEYBYTES ];
  uint8_t session_id[ STL_SESSION_ID_SZ ];
  bool    done;
};

typedef struct stl_s0_server_hs stl_s0_server_hs_t;

STL_PROTOTYPES_BEGIN

uint64_t
stl_s0_server_handshake( stl_s0_server_params_t const * server,
                         stl_net_ctx_t const *          ctx,
                         uint8_t const *                in,
                         uint64_t                       in_sz,
                         uint8_t                        out[ static STL_MTU ],
                         stl_s0_server_hs_t *           hs );

/* stl_s0_server_rotate_keys re-generates the ephemeral keys
   (cookie_secret and signature_seed).  This invalidates any active
   handshakes.  (Established session IDs are not affected) */

void
stl_s0_server_rotate_keys( stl_s0_server_params_t * server );

STL_PROTOTYPES_END

#endif /* HEADER_stl_s0_server_h */
