#ifndef HEADER_stl_s0_client_h
#define HEADER_stl_s0_client_h

#include "stl_base.h"
#include "stl_proto.h"
#include <stdbool.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_shorthash_siphash24.h>

struct stl_s0_client_params {

  /* identity is a compound structure of the identity private and
     public key */
  uint8_t identity[ crypto_sign_ed25519_SECRETKEYBYTES ];

  /* cookie_secret is an ephemeral key used to create and verify
     handshake cookies. */
  uint8_t cookie_secret[ crypto_shorthash_siphash24_KEYBYTES ];

};

typedef struct stl_s0_client_params stl_s0_client_params_t;

/* TODO: decouple handshake, connection, and client objects*/
struct stl_s0_client_hs {
  uint8_t server_token[ STL_TOKEN_SZ ]; /* TODO: unnecessary? */
  uint8_t client_token[ STL_TOKEN_SZ ];
  crypto_hash_sha256_state transcript;
  uint8_t state;
  uint8_t session_id[ STL_SESSION_ID_SZ ];
  uint8_t server_identity[ crypto_sign_ed25519_PUBLICKEYBYTES ];
};

typedef struct stl_s0_client_hs stl_s0_client_hs_t;

STL_PROTOTYPES_BEGIN

stl_s0_client_hs_t *
stl_s0_client_hs_new( void * hs );

uint64_t
stl_s0_client_initial( stl_s0_client_params_t const * client,
                       stl_s0_client_hs_t const *     hs,
                       uint8_t                        pkt_out[ static STL_MTU ] );

uint64_t
stl_s0_client_handshake( stl_s0_client_params_t const * client,
                         stl_s0_client_hs_t *           hs,
                         uint8_t const *                pkt_in,
                         uint64_t                       pkt_in_sz,
                         uint8_t                        pkt_out[ static STL_MTU ] );

/*
  stl_s0_encode_appdata is a temporary function that encodes the payload into
  pkt_out using STL 0x1. It takes session details from hs. It returns the total
  number of bytes encoded, or a negative value for err
*/
int64_t
stl_s0_encode_appdata( stl_s0_client_hs_t * hs,
                     const uint8_t *      payload, /* TODO: create a 0cp mode */
                     uint16_t             payload_sz,
                     uint8_t              pkt_out[ static STL_MTU ] );

STL_PROTOTYPES_END

#endif /* HEADER_stl_s0_client_h */
