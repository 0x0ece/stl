#include "stl_private.h"
#include <sodium/randombytes.h>
#include <sodium/crypto_shorthash_siphash24.h>
#include <sodium/crypto_verify_16.h>

uint8_t *
stl_cookie_create( uint8_t                     cookie[ static STL_COOKIE_SZ ],
                   stl_cookie_claims_t const * ctx,
                   uint8_t const               cookie_secret[ static crypto_shorthash_siphash24_KEYBYTES ] ) {

  crypto_shorthash_siphash24(
      /* out */ cookie,
      /* in  */ ctx->b, STL_COOKIE_CLAIMS_B_SZ,
      /* key */ cookie_secret );

  return cookie;

}

int
stl_cookie_verify( uint8_t const               cookie[ static STL_COOKIE_SZ ],
                   stl_cookie_claims_t const * ctx,
                   uint8_t const               cookie_secret[ static crypto_shorthash_siphash24_KEYBYTES ] ) {

  uint8_t expected[ crypto_shorthash_siphash24_BYTES ];
  crypto_shorthash_siphash24(
      /* out */ expected,
      /* in  */ ctx->b, STL_COOKIE_CLAIMS_B_SZ,
      /* key */ cookie_secret );

  return (*(volatile uint64_t *)expected) == (*(volatile uint64_t *)cookie);
}

void
stl_gen_session_id( uint8_t session_id[ static STL_SESSION_ID_SZ ] ) {

  randombytes_buf( session_id, STL_SESSION_ID_SZ );

}
