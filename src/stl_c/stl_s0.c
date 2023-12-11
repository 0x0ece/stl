#include "stl_base.h"
#include "stl_s0_server.h"
#include "stl_s0_client.h"
#include "stl_proto.h"
#include "stl_private.h"
#include <stdint.h>
#include <string.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_shorthash_siphash24.h>
#include <sodium/randombytes.h>

static char const sign_prefix_server[32] =
  "STL v0 s0 server transcript     ";

static char const sign_prefix_client[32] =
  "STL v0 s0 client transcript     ";

static uint64_t
stl_s0_server_handle_initial( stl_s0_server_params_t const * server,
                              stl_net_ctx_t const *          ctx,
                              stl_s0_hs_pkt_t const *        pkt,
                              uint8_t                        out[ static STL_MTU ],
                              stl_s0_server_hs_t *           hs ) {

  (void)pkt;

  /* Create a SYN cookie */

  stl_cookie_claims_t claims[1];
  memset( claims, 0, sizeof(claims) );
  claims->net   = *ctx;
  claims->suite = STL_SUITE_S0;

  uint8_t cookie[ STL_COOKIE_SZ ];
  stl_cookie_create( cookie, claims, server->cookie_secret );

  /* Send back the cookie and our server identity */

  stl_s0_hs_pkt_t * out_pkt = (stl_s0_hs_pkt_t *)out;
  memset( out_pkt, 0, sizeof(*out_pkt) );

  out_pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_SERVER_CONTINUE );
  out_pkt->hs.suite = STL_SUITE_S0;
  memcpy( out_pkt->hs.cookie,    cookie,            STL_COOKIE_SZ );
  memcpy( out_pkt->client_token, pkt->client_token, STL_TOKEN_SZ  );
  memcpy( out_pkt->server_token, server->token,     STL_TOKEN_SZ  );
  crypto_sign_ed25519_sk_to_pk( out_pkt->identity, server->identity );

  /* Return info to user */

  memset( hs, 0, sizeof(stl_s0_server_hs_t) );
  hs->done = 0;

  return sizeof(stl_s0_hs_pkt_t);
}

static uint64_t
stl_s0_server_handle_accept( stl_s0_server_params_t const * server,
                             stl_net_ctx_t const *          ctx,
                             stl_s0_hs_pkt_t const *        pkt,
                             uint8_t                        out[ static STL_MTU ],
                             stl_s0_server_hs_t *           hs ) {

  /* Verify the SYN cookie */

  stl_cookie_claims_t claims[1];
  memset( claims, 0, sizeof(claims) );
  claims->net   = *ctx;
  claims->suite = STL_SUITE_S0;

  if( !stl_cookie_verify( pkt->hs.cookie, claims, server->cookie_secret ) )
    return 0UL;

  /* Create the transcript hash */

  uint8_t server_pubkey[32];
  crypto_sign_ed25519_sk_to_pk( server_pubkey, server->identity );

  crypto_hash_sha256_state state0[1];
  crypto_hash_sha256_state state1[1];
  crypto_hash_sha256_init( state0 );
  crypto_hash_sha256_update( state0, server_pubkey,     crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state0, pkt->identity,     crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state0, server->token,     STL_TOKEN_SZ );
  crypto_hash_sha256_update( state0, pkt->client_token, STL_TOKEN_SZ );
  crypto_hash_sha256_update( state0, (uint8_t const *)&claims->suite, sizeof(uint16_t) );
  *state1 = *state0;

  /* Verify signature */

  uint8_t client_signed_msg[64];
  memcpy( client_signed_msg, sign_prefix_client, 32 );
  crypto_hash_sha256_final( state0, client_signed_msg+32 );

  int vfy_err = crypto_sign_ed25519_verify_detached(
      pkt->verify, client_signed_msg, sizeof(client_signed_msg), pkt->identity );
  if( vfy_err ) return 0UL;

  /* Derive session ID */

  uint8_t session_id[ STL_SESSION_ID_SZ ];
  stl_gen_session_id( session_id );

  uint8_t server_commitment[ crypto_hash_sha256_BYTES ];
  crypto_hash_sha256_update( state1, session_id, STL_SESSION_ID_SZ );
  crypto_hash_sha256_final( state1, server_commitment );

  /* Send back response */

  stl_s0_hs_pkt_t * out_pkt = (stl_s0_hs_pkt_t *)out;
  memset( out_pkt, 0, sizeof(*out_pkt) );

  out_pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_SERVER_ACCEPT );
  out_pkt->hs.suite = STL_SUITE_S0;
  memcpy( out_pkt->hs.cookie,    pkt->hs.cookie,    STL_COOKIE_SZ );
  memcpy( out_pkt->client_token, pkt->client_token, STL_TOKEN_SZ  );
  memcpy( out_pkt->server_token, server->token,     STL_TOKEN_SZ  );
  memcpy( out_pkt->hs.base.session_id, session_id, STL_SESSION_ID_SZ );

  /* Sign verify */

  uint8_t server_signed_msg[64];
  memcpy( server_signed_msg,    sign_prefix_server, 32 );
  memcpy( server_signed_msg+32, server_commitment,  32 );

  crypto_sign_ed25519_detached(
      out_pkt->verify, NULL, server_signed_msg, sizeof(server_signed_msg), server->identity );

  /* Return info to caller */

  memset( hs, 0, sizeof(stl_s0_server_hs_t) );
  hs->done = 1;
  memcpy( hs->session_id, session_id, STL_SESSION_ID_SZ );
  memcpy( &hs->identity, pkt->identity, crypto_sign_ed25519_PUBLICKEYBYTES );

  return sizeof(stl_s0_hs_pkt_t);
}

uint64_t
stl_s0_server_handshake( stl_s0_server_params_t const * server,
                         stl_net_ctx_t const *          ctx,
                         uint8_t const *                in,
                         uint64_t                       in_sz,
                         uint8_t                        out[ static STL_MTU ],
                         stl_s0_server_hs_t *           hs ) {

  if( STL_UNLIKELY( in_sz < 1200UL ) )
    return 0UL;

  stl_s0_hs_pkt_t const * pkt = (stl_s0_hs_pkt_t const *)in;

  if( STL_UNLIKELY( ( stl_hdr_version( &pkt->hs.base ) != STL_V0 ) |
                    ( pkt->hs.suite != STL_SUITE_S0 ) ) )
    return 0UL;

  switch( stl_hdr_type( &pkt->hs.base ) ) {
  case STL_TYPE_HS_CLIENT_INITIAL:
    return stl_s0_server_handle_initial( server, ctx, pkt, out, hs );
  case STL_TYPE_HS_CLIENT_ACCEPT:
    return stl_s0_server_handle_accept ( server, ctx, pkt, out, hs );
  default:
    return 0UL;
  }

}

void
stl_s0_server_rotate_secrets( stl_s0_server_params_t * server ) {

  randombytes_buf( server->cookie_secret, crypto_shorthash_siphash24_KEYBYTES );

}

stl_s0_client_hs_t *
stl_s0_client_hs_new( void * mem ) {

  stl_s0_client_hs_t * hs = (stl_s0_client_hs_t *)mem;
  memset( hs, 0, sizeof(stl_s0_client_hs_t) );
  hs->state = STL_TYPE_HS_CLIENT_INITIAL;
  return hs;

}

uint64_t
stl_s0_client_initial( stl_s0_client_params_t const * client,
                       stl_s0_client_hs_t const *     hs,
                       uint8_t                        pkt_out[ static STL_MTU ] ) {

  stl_s0_hs_pkt_t * pkt = (stl_s0_hs_pkt_t *)pkt_out;
  memset( pkt, 0, 1200 );  /* TODO fix magic constant */
  pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_CLIENT_INITIAL );
  pkt->hs.suite = STL_SUITE_S0;
  crypto_sign_ed25519_sk_to_pk( pkt->identity, client->identity );
  memcpy( pkt->client_token, hs->client_token, STL_TOKEN_SZ );
  return 1200;

}

static uint64_t
stl_s0_client_handle_continue( stl_s0_client_params_t const * client,
                               stl_s0_hs_pkt_t const *        pkt,
                               uint8_t                        out[ static STL_MTU ],
                               stl_s0_client_hs_t *           hs ) {

  if( STL_UNLIKELY( stl_hdr_type( &pkt->hs.base ) != STL_TYPE_HS_SERVER_CONTINUE ) )
    return 0UL;

  /* Ignore packet if server identity is unexpected */

  if( STL_UNLIKELY( 0!=memcmp( pkt->identity, hs->server_identity, crypto_sign_ed25519_PUBLICKEYBYTES ) ) )
    return 0UL;

  /* Create transcript hash */

  uint8_t client_identity[ crypto_sign_ed25519_PUBLICKEYBYTES ];
  crypto_sign_ed25519_sk_to_pk( client_identity, client->identity );

  crypto_hash_sha256_state state[1];
  crypto_hash_sha256_init( state );
  crypto_hash_sha256_update( state, hs->server_identity, crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state, client_identity,     crypto_sign_ed25519_PUBLICKEYBYTES );
  crypto_hash_sha256_update( state, pkt->server_token,   STL_TOKEN_SZ );
  crypto_hash_sha256_update( state, hs->client_token,    STL_TOKEN_SZ );
  crypto_hash_sha256_update( state, (uint8_t const *)&pkt->hs.suite, sizeof(uint16_t) );
  hs->transcript = *state;

  uint8_t client_signed_msg[ 64 ];
  memcpy( client_signed_msg, sign_prefix_client, 32 );
  crypto_hash_sha256_final( state, client_signed_msg+32 );

  /* Assemble response */

  memset( out, 0, 1200UL );
  stl_s0_hs_pkt_t * out_pkt = (stl_s0_hs_pkt_t *)out;

  /* Sign */

  int sign_err = crypto_sign_ed25519_detached( out_pkt->verify, NULL, client_signed_msg, sizeof(client_signed_msg), client->identity );
  if( STL_UNLIKELY( sign_err ) ) return 0UL;

  out_pkt->hs.base.version_type = stl_hdr_version_type( STL_V0, STL_TYPE_HS_CLIENT_ACCEPT );
  out_pkt->hs.suite = STL_SUITE_S0;
  memcpy( out_pkt->hs.cookie,    pkt->hs.cookie,    STL_COOKIE_SZ );
  memcpy( out_pkt->identity,     client_identity,   crypto_sign_ed25519_PUBLICKEYBYTES );
  memcpy( out_pkt->client_token, pkt->client_token, STL_TOKEN_SZ );
  memcpy( out_pkt->server_token, pkt->server_token, STL_TOKEN_SZ );

  hs->state = STL_TYPE_HS_SERVER_CONTINUE;

  return 1200UL;
}

static uint64_t
stl_s0_client_handle_accept( stl_s0_hs_pkt_t const * pkt,
                             stl_s0_client_hs_t *    hs ) {

  if( STL_UNLIKELY( stl_hdr_type( &pkt->hs.base ) != STL_TYPE_HS_SERVER_ACCEPT ) )
    return 0UL;

  /* Derive server commitment */

  crypto_hash_sha256_state state[1];
  *state = hs->transcript;
  crypto_hash_sha256_update( state, pkt->hs.base.session_id, STL_SESSION_ID_SZ );

  /* Verify server signature */

  uint8_t signed_msg[64];
  memcpy( signed_msg, sign_prefix_server, 32 );
  crypto_hash_sha256_final( state, signed_msg+32 );

  int vfy_err = crypto_sign_ed25519_verify_detached(
      pkt->verify, signed_msg, sizeof(signed_msg), hs->server_identity );
  if( vfy_err ) return 0UL;

  /* Success!  Return info to caller */

  hs->state = STL_TYPE_HS_SERVER_ACCEPT;
  memcpy( hs->session_id, pkt->hs.base.session_id, STL_SESSION_ID_SZ );

  return 0UL;
}

uint64_t
stl_s0_client_handshake( stl_s0_client_params_t const * client,
                         stl_s0_client_hs_t *           hs,
                         uint8_t const *                pkt_in,
                         uint64_t                       pkt_in_sz,
                         uint8_t                        pkt_out[ static STL_MTU ] ) {

  if( STL_UNLIKELY( pkt_in_sz < sizeof(stl_s0_hs_pkt_t) ) )
    return 0UL;

  stl_s0_hs_pkt_t const * pkt = (stl_s0_hs_pkt_t const *)pkt_in;

  if( STL_UNLIKELY(
      /* Verify protocol version */
      ( stl_hdr_version( &pkt->hs.base ) != STL_V0       ) |
      ( pkt->hs.suite                    != STL_SUITE_S0 ) |
      /* Verify client token */
      ( 0!=memcmp( pkt->client_token, hs->client_token, STL_TOKEN_SZ ) ) ) )
    return 0UL;

  switch( hs->state ) {
  case STL_TYPE_HS_CLIENT_INITIAL:
    return stl_s0_client_handle_continue( client, pkt, pkt_out, hs );
  case STL_TYPE_HS_SERVER_CONTINUE:
    return stl_s0_client_handle_accept  ( pkt, hs );
  default:
    return 0UL;
  }

}
