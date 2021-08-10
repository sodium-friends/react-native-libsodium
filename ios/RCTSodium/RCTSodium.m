#import "RCTBridgeModule.h"
#import "RCTUtils.h"
#import "RCTSodium.h"
#import "sodium.h"
#include "macros.h"

@implementation RCTSodium

static bool isInitialized;

NSString * const ESODIUM = @"ESODIUM";
NSString * const ERR_BAD_KEY = @"BAD_KEY";
NSString * const ERR_BAD_SUBKEY = @"BAD_SUBKEY";
NSString * const ERR_BAD_MAC = @"BAD_MAC";
NSString * const ERR_BAD_MSG = @"BAD_MSG";
NSString * const ERR_BAD_NONCE = @"BAD_NONCE";
NSString * const ERR_BAD_CIPHERTEXT = @"BAD_CIPHERTEXT";
NSString * const ERR_BAD_CIPHERTEXT_LENGTH = @"BAD_CIPHERTEXT_LENGTH";
NSString * const ERR_BAD_MESSAGE_LENGTH = @"BAD_MESSAGE_LENGTH";
NSString * const ERR_BAD_NSEC = @"BAD_NSEC";
NSString * const ERR_BAD_NPUB = @"BAD_NPUB";
NSString * const ERR_BAD_SEED = @"BAD_SEED";
NSString * const ERR_BAD_EC_POINT = @"BAD_EC_POINT";
NSString * const ERR_BAD_SCALAR = @"BAD_SCALAR";
NSString * const ERR_BAD_SIG = @"BAD_SIG";
NSString * const ERR_BAD_CONTEXT = @"BAD_CONTEXT";
NSString * const ERR_BAD_STATE = @"ERR_BAD_STATE";
NSString * const ERR_BAD_HEADER = @"ERR_BAD_HEADER";
NSString * const ERR_FAILURE = @"FAILURE";
NSString * const ERR_BAD_OUTPUT = @"BAD_OUTPUT";
NSString * const ERR_BAD_PWD = @"BAD_PWD";
NSString * const ERR_BAD_SALT = @"BAD_SALT";
NSString * const ERR_BAD_OPS = @"BAD_OPS";
NSString * const ERR_BAD_MEM = @"BAD_MEM";
NSString * const ERR_BAD_ALG = @"BAD_ALG";

RCT_EXPORT_MODULE()

// Example method
// See // https://reactnative.dev/docs/native-modules-ios

+ (void) initialize
{
    [super initialize];
    isInitialized = sodium_init() != -1;
}

// *****************************************************************************
// * Sodium constants
// *****************************************************************************
- (NSDictionary *)constantsToExport
{
  return @{
    @"crypto_aead_xchacha20poly1305_ietf_KEYBYTES": @ crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    @"crypto_aead_xchacha20poly1305_ietf_NPUBBYTES": @ crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    @"crypto_aead_xchacha20poly1305_ietf_ABYTES": @ crypto_aead_xchacha20poly1305_ietf_ABYTES,
    @"crypto_core_ed25519_SCALARBYTES": @ crypto_core_ed25519_SCALARBYTES,
    @"crypto_core_ed25519_BYTES": @ crypto_core_ed25519_BYTES,
    @"crypto_core_ed25519_UNIFORMBYTES": @ crypto_core_ed25519_UNIFORMBYTES,
    @"crypto_pwhash_BYTES_MIN": @ crypto_pwhash_BYTES_MIN,
    @"crypto_pwhash_BYTES_MAX": @ crypto_pwhash_BYTES_MAX,
    @"crypto_pwhash_PASSWD_MIN": @ crypto_pwhash_PASSWD_MIN,
    @"crypto_pwhash_PASSWD_MAX": @ crypto_pwhash_PASSWD_MAX,
    @"crypto_pwhash_SALTBYTES": @ crypto_pwhash_SALTBYTES,
    @"crypto_pwhash_OPSLIMIT_MIN": @ crypto_pwhash_OPSLIMIT_MIN,
    @"crypto_pwhash_OPSLIMIT_MAX": @ crypto_pwhash_OPSLIMIT_MAX,
    @"crypto_pwhash_MEMLIMIT_MIN": @ crypto_pwhash_MEMLIMIT_MIN,
    @"crypto_pwhash_MEMLIMIT_MAX": @ crypto_pwhash_MEMLIMIT_MAX,
    @"crypto_pwhash_ALG_DEFAULT": @ crypto_pwhash_ALG_DEFAULT,
    @"crypto_pwhash_ALG_ARGON2I13": @ crypto_pwhash_ALG_ARGON2I13,
    @"crypto_pwhash_ALG_ARGON2ID13": @ crypto_pwhash_ALG_ARGON2ID13,
    @"crypto_pwhash_BYTES_MIN": @ crypto_pwhash_BYTES_MIN,
    @"crypto_pwhash_BYTES_MAX": @ crypto_pwhash_BYTES_MAX,
    @"crypto_pwhash_PASSWD_MIN": @ crypto_pwhash_PASSWD_MIN,
    @"crypto_pwhash_PASSWD_MAX": @ crypto_pwhash_PASSWD_MAX,
    @"crypto_pwhash_SALTBYTES": @ crypto_pwhash_SALTBYTES,
    @"crypto_pwhash_STRBYTES": @ crypto_pwhash_STRBYTES,
    @"crypto_pwhash_OPSLIMIT_MIN": @ crypto_pwhash_OPSLIMIT_MIN,
    @"crypto_pwhash_OPSLIMIT_MAX": @ crypto_pwhash_OPSLIMIT_MAX,
    @"crypto_pwhash_MEMLIMIT_MIN": @ crypto_pwhash_MEMLIMIT_MIN,
    @"crypto_pwhash_MEMLIMIT_MAX": @ crypto_pwhash_MEMLIMIT_MAX,
    @"crypto_pwhash_OPSLIMIT_INTERACTIVE": @ crypto_pwhash_OPSLIMIT_INTERACTIVE,
    @"crypto_pwhash_MEMLIMIT_INTERACTIVE": @ crypto_pwhash_MEMLIMIT_INTERACTIVE,
    @"crypto_pwhash_OPSLIMIT_MODERATE": @ crypto_pwhash_OPSLIMIT_MODERATE,
    @"crypto_pwhash_MEMLIMIT_MODERATE": @ crypto_pwhash_MEMLIMIT_MODERATE,
    @"crypto_pwhash_OPSLIMIT_SENSITIVE": @ crypto_pwhash_OPSLIMIT_SENSITIVE,
    @"crypto_pwhash_MEMLIMIT_SENSITIVE": @ crypto_pwhash_MEMLIMIT_SENSITIVE,
    @"crypto_scalarmult_ed25519_BYTES": @ crypto_scalarmult_ed25519_BYTES,
    @"crypto_scalarmult_ed25519_SCALARBYTES": @ crypto_scalarmult_ed25519_SCALARBYTES,
    @"crypto_generichash_STATEBYTES": @ 384,
    @"crypto_generichash_KEYBYTES_MIN": @ crypto_generichash_KEYBYTES_MIN,
    @"crypto_generichash_KEYBYTES_MAX": @ crypto_generichash_KEYBYTES_MAX,
    @"crypto_generichash_BYTES": @ crypto_generichash_BYTES,
    @"crypto_generichash_BYTES_MIN": @ crypto_generichash_BYTES_MIN,
    @"crypto_generichash_BYTES_MAX": @ crypto_generichash_BYTES_MAX,
    @"crypto_kdf_KEYBYTES": @ crypto_kdf_KEYBYTES,
    @"crypto_kdf_BYTES_MIN": @ crypto_kdf_BYTES_MIN,
    @"crypto_kdf_BYTES_MAX": @ crypto_kdf_BYTES_MAX,
    @"crypto_kdf_CONTEXTBYTES": @ crypto_kdf_CONTEXTBYTES,
    @"crypto_secretstream_xchacha20poly1305_STATEBYTES":@ 52,
    @"crypto_secretstream_xchacha20poly1305_ABYTES": @ crypto_secretstream_xchacha20poly1305_ABYTES,
    @"crypto_secretstream_xchacha20poly1305_HEADERBYTES": @ crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    @"crypto_secretstream_xchacha20poly1305_KEYBYTES": @ crypto_secretstream_xchacha20poly1305_KEYBYTES,
    @"crypto_secretstream_xchacha20poly1305_TAGBYTES": @ 1,
    @"crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX": @ crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX,
    @"_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE": @ crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    @"_crypto_secretstream_xchacha20poly1305_TAG_PUSH": @ crypto_secretstream_xchacha20poly1305_TAG_PUSH,
    @"_crypto_secretstream_xchacha20poly1305_TAG_REKEY": @ crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    @"_crypto_secretstream_xchacha20poly1305_TAG_FINAL": @ crypto_secretstream_xchacha20poly1305_TAG_FINAL,

  };
}

- (NSData *)to_bytes:(NSArray *)array; {
    NSMutableData *data = [NSMutableData data];
    [array enumerateObjectsUsingBlock:^(NSNumber* number, NSUInteger index, BOOL* stop) {
        uint8_t tmp = number.unsignedCharValue;
        [data appendBytes:(void *)(&tmp)length:1];
    }];

    return data;
}

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_secretbox_easy:(NSArray*)c m:(NSArray*)m n:(NSArray*)n k:(NSArray*)k)
{
  RN_ARG_BUFFER(k, crypto_secretbox_KEYBYTES, ERR_BAD_KEY)
  RN_ARG_BUFFER(n, crypto_secretbox_NONCEBYTES, ERR_BAD_NONCE)
  RN_ARG_BUFFER_NO_CHECK(m)

  unsigned long long clen_check = mlen + crypto_secretbox_MACBYTES;
  RN_RESULT_BUFFER(c, clen_check, ERR_BAD_CIPHERTEXT)

  RN_CHECK_FAILURE(crypto_secretbox_easy(c_data, m_data, mlen, n_data, k_data))

  RN_RETURN_BUFFER(c)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_aead_xchacha20poly1305_ietf_keygen:(NSArray*)k)
{
  RN_RESULT_BUFFER(k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, ERR_BAD_KEY)

  crypto_aead_xchacha20poly1305_ietf_keygen(k_data);

  RN_RETURN_BUFFER(k)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  randombytes_buf:(NSArray*)buf)
{
  RN_RESULT_BUFFER_NO_CHECK(buf)

  randombytes_buf(buf_data, buflen);

  RN_RETURN_BUFFER(buf)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_aead_xchacha20poly1305_ietf_encrypt:(NSArray *) c
                                              m:(NSArray *) m
                                              ad:(NSArray *) ad
                                              nsec:(NSArray *) nsec
                                              npub:(NSArray *) npub
                                              k:(NSArray *) k)
{
  RN_ARG_BUFFER_NO_CHECK(m)
  RN_ARG_BUFFER_OR_NULL(ad)
  RN_ARG_BUFFER(npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, ERR_BAD_NPUB)
  RN_ARG_BUFFER(k, crypto_secretbox_KEYBYTES, ERR_BAD_KEY)

  unsigned long long clen_check = mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  RN_RESULT_BUFFER(c, clen_check, ERR_BAD_CIPHERTEXT)

  RN_CHECK_FAILURE(crypto_aead_xchacha20poly1305_ietf_encrypt(c_data, &clen,
                                                              m_data, mlen,
                                                              ad_data, adlen,
                                                              NULL,
                                                              npub_data,
                                                              k_data))

  RN_RETURN_BUFFER(c)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_aead_xchacha20poly1305_ietf_decrypt:(NSArray *)m
                                              nsec:(NSArray *) nsec
                                              c:(NSArray *) c
                                              ad:(NSArray *) ad
                                              npub:(NSArray *) npub
                                              k:(NSArray *) k)
{
  RN_ARG_BUFFER_NO_CHECK(c)
  RN_ARG_BUFFER_OR_NULL(ad)
  RN_ARG_BUFFER(npub, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, ERR_BAD_NPUB)
  RN_ARG_BUFFER(k, crypto_secretbox_KEYBYTES, ERR_BAD_KEY)

  unsigned long long mlen_check = clen - crypto_aead_xchacha20poly1305_ietf_ABYTES;
  RN_RESULT_BUFFER(m, mlen_check, ERR_BAD_MSG)

  RN_CHECK_FAILURE(crypto_aead_xchacha20poly1305_ietf_decrypt(m_data, &mlen,
                                                              NULL,
                                                              c_data, clen,
                                                              ad_data, adlen,
                                                              npub_data,
                                                              k_data))

  RN_RETURN_BUFFER(m)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_core_ed25519_scalar_random:(NSArray *)r) {
  RN_RESULT_BUFFER(r, crypto_core_ed25519_SCALARBYTES, ERR_BAD_SCALAR)

  crypto_core_ed25519_scalar_random(r_data);

  RN_RETURN_BUFFER(r)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_core_ed25519_add:(NSArray *)r p:(NSArray *) p q:(NSArray *) q)
{
  RN_RESULT_BUFFER(r, crypto_core_ed25519_BYTES, ERR_BAD_EC_POINT)
  RN_ARG_BUFFER(p, crypto_core_ed25519_BYTES, ERR_BAD_EC_POINT);
  RN_ARG_BUFFER(q, crypto_core_ed25519_BYTES, ERR_BAD_EC_POINT);

  RN_CHECK_FAILURE(crypto_core_ed25519_add(r_data, p_data, q_data))

  RN_RETURN_BUFFER(r)
}


RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_core_ed25519_sub:(NSArray *)r p:(NSArray *) p q:(NSArray *) q)
{
  RN_RESULT_BUFFER(r, crypto_core_ed25519_BYTES, ERR_BAD_EC_POINT)
  RN_ARG_BUFFER(p, crypto_core_ed25519_BYTES, ERR_BAD_EC_POINT);
  RN_ARG_BUFFER(q, crypto_core_ed25519_BYTES, ERR_BAD_EC_POINT);

  RN_CHECK_FAILURE(crypto_core_ed25519_sub(r_data, p_data, q_data))

  RN_RETURN_BUFFER(r)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_core_ed25519_from_uniform:(NSArray *)p r:(NSArray *) r)
{
  RN_RESULT_BUFFER(p, crypto_core_ed25519_BYTES, ERR_BAD_EC_POINT)
  RN_ARG_BUFFER(r, crypto_core_ed25519_UNIFORMBYTES, ERR_BAD_SEED)

  RN_CHECK_FAILURE(crypto_core_ed25519_from_uniform(p_data, r_data))

  RN_RETURN_BUFFER(p)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_pwhash:(NSArray *)out
                passwd:(NSArray *) passwd
                salt:(NSArray *) salt
                opslimit:(nonnull NSNumber *)
                opslimit memlimit:(nonnull NSNumber *)
                memlimit alg:(nonnull NSNumber *) alg)
{
  RN_RESULT_BUFFER_MIN_MAX(out, crypto_pwhash_BYTES_MIN, crypto_pwhash_BYTES_MAX, ERR_BAD_OUTPUT)
  RN_ARG_CONST_BUFFER_MIN_MAX(passwd, crypto_pwhash_PASSWD_MIN, crypto_pwhash_PASSWD_MAX, ERR_BAD_PWD)
  RN_ARG_BUFFER(salt, crypto_pwhash_SALTBYTES, ERR_BAD_SALT)
  RN_ULL_MIN_MAX(opslimit, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_OPSLIMIT_MAX, ERR_BAD_OPS)
  RN_INT_MIN_MAX(memlimit, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_MEMLIMIT_MAX, ERR_BAD_MEM)

  int alg_val = [alg intValue];
  if (alg_val != crypto_pwhash_ALG_DEFAULT
      && alg_val != crypto_pwhash_ALG_ARGON2I13
      && alg_val != crypto_pwhash_ALG_ARGON2ID13)
    return ERR_BAD_ALG;

  RN_CHECK_FAILURE(crypto_pwhash(out_data, outlen,
                                 passwd_data, passwdlen,
                                 salt_data, opslimit_val,
                                 memlimit_val, alg_val))

  RN_RETURN_BUFFER(out)
}

RCT_EXPORT_METHOD(
  crypto_pwhash_async:(NSArray *)out
                passwd:(NSArray *) passwd
                salt:(NSArray *) salt
                opslimit:(nonnull NSNumber *)
                opslimit memlimit:(nonnull NSNumber *)
                memlimit alg:(nonnull NSNumber *) alg
                resolver:(RCTPromiseResolveBlock) resolve
                rejecter:(RCTPromiseRejectBlock) reject)
{
  RN_RESULT_BUFFER_NO_CHECK_PROMISE(out, ERR_BAD_OUTPUT)
  if (outlen < crypto_pwhash_BYTES_MIN || outlen > crypto_pwhash_BYTES_MAX) {
    reject(ERR_BAD_OUTPUT, ERR_BAD_OUTPUT, nil);
    return;
  }

  RN_ARG_CONST_BUFFER_NO_CHECK(passwd)
  if (passwdlen < crypto_pwhash_PASSWD_MIN || passwdlen > crypto_pwhash_PASSWD_MAX) {
    reject(ERR_BAD_PWD, ERR_BAD_PWD, nil);
    return;
  }

  RN_ARG_BUFFER_NO_CHECK(salt)
  if (saltlen != crypto_pwhash_SALTBYTES) {
    reject(ERR_BAD_SALT, ERR_BAD_SALT, nil);
    return;
  }

  NSNumber *OPS_MIN;
  NSNumber *OPS_MAX;

  OPS_MIN = [NSNumber numberWithUnsignedLongLong:crypto_pwhash_OPSLIMIT_MIN];
  OPS_MAX = [NSNumber numberWithUnsignedLongLong:crypto_pwhash_OPSLIMIT_MAX];

  if ([opslimit compare:OPS_MIN] == NSOrderedAscending
    || [opslimit compare:OPS_MAX] == NSOrderedDescending) {
    reject(ERR_BAD_OPS, ERR_BAD_OPS, nil);
    return;
  }
  unsigned long long opslimit_val = [opslimit unsignedLongLongValue];

  NSNumber *MEM_MIN;
  NSNumber *MEM_MAX;

  MEM_MIN = [NSNumber numberWithUnsignedInt:crypto_pwhash_MEMLIMIT_MIN];
  MEM_MAX = [NSNumber numberWithUnsignedInt:crypto_pwhash_MEMLIMIT_MAX];

  if ([memlimit compare:MEM_MIN] == NSOrderedAscending
    || [memlimit compare:MEM_MAX] == NSOrderedDescending) {
    reject(ERR_BAD_MEM, ERR_BAD_MEM, nil);
    return;
  }
  int memlimit_val = [memlimit intValue];

  int alg_val = [alg intValue];
  if (alg_val != crypto_pwhash_ALG_DEFAULT
      && alg_val != crypto_pwhash_ALG_ARGON2I13
      && alg_val != crypto_pwhash_ALG_ARGON2ID13) {
    reject(ERR_BAD_ALG, ERR_BAD_ALG, nil);
    return;
  }

  int check = crypto_pwhash(out_data, outlen,
                                 passwd_data, passwdlen,
                                 salt_data, opslimit_val,
                                 memlimit_val, alg_val);

  if (check != 0) {
    reject(ERR_FAILURE, @"crypto_pwhash execution failed.", nil);
    return;
  }

  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: outlen];
  RN_COPY_DATA(res, out, outlen)
  resolve([res copy]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_scalarmult_ed25519:(NSArray *)q n:(NSArray *) n p:(NSArray *) p)
{
  RN_RESULT_BUFFER(q, crypto_scalarmult_ed25519_BYTES, ERR_BAD_EC_POINT)
  RN_ARG_BUFFER(n, crypto_scalarmult_ed25519_SCALARBYTES, ERR_BAD_SCALAR)
  RN_ARG_BUFFER(p, crypto_scalarmult_ed25519_BYTES, ERR_BAD_EC_POINT)

  RN_CHECK_FAILURE(crypto_scalarmult_ed25519(q_data, n_data, p_data))

  RN_RETURN_BUFFER(q)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_scalarmult_ed25519_noclamp:(NSArray *)q n:(NSArray *) n p:(NSArray *) p)
{
  RN_RESULT_BUFFER(q, crypto_scalarmult_ed25519_BYTES, ERR_BAD_EC_POINT)
  RN_ARG_BUFFER(n, crypto_scalarmult_ed25519_SCALARBYTES, ERR_BAD_SCALAR)
  RN_ARG_BUFFER(p, crypto_scalarmult_ed25519_BYTES, ERR_BAD_EC_POINT)

  RN_CHECK_FAILURE(crypto_scalarmult_ed25519_noclamp(q_data, n_data, p_data))

  RN_RETURN_BUFFER(q)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_scalarmult_ed25519_base:(NSArray *)q n:(NSArray *) n)
{
  RN_RESULT_BUFFER(q, crypto_scalarmult_ed25519_BYTES, ERR_BAD_EC_POINT)
  RN_ARG_BUFFER(n, crypto_scalarmult_ed25519_SCALARBYTES, ERR_BAD_SCALAR)

  RN_CHECK_FAILURE(crypto_scalarmult_ed25519_base(q_data, n_data))

  RN_RETURN_BUFFER(q)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_scalarmult_ed25519_base_noclamp:(NSArray *)q n:(NSArray *) n)
{
  RN_RESULT_BUFFER(q, crypto_scalarmult_ed25519_BYTES, ERR_BAD_EC_POINT)
  RN_ARG_BUFFER(n, crypto_scalarmult_ed25519_SCALARBYTES, ERR_BAD_SCALAR)

  RN_CHECK_FAILURE(crypto_scalarmult_ed25519_base_noclamp(q_data, n_data))

  RN_RETURN_BUFFER(q)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_generichash_init:(NSArray *)state key:(NSArray *) key outlen: (nonnull NSNumber *) outlen)
{
  RN_RESULT_BUFFER(state, crypto_generichash_statebytes(), ERR_BAD_STATE)
  crypto_generichash_state *c_state = (crypto_generichash_state *) state_data;
  RN_ARG_BUFFER_MIN_MAX_OR_NULL(key, crypto_generichash_KEYBYTES_MIN, crypto_generichash_KEYBYTES_MAX, ERR_BAD_KEY)

  RN_CHECK_FAILURE(crypto_generichash_init(c_state, key_data, keylen, [outlen unsignedIntValue]))

  RN_RETURN_BUFFER(state)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_generichash_update:(NSArray *)state in:(NSArray *) in)
{
  RN_ARG_BUFFER(state, crypto_generichash_statebytes(), ERR_BAD_STATE)
  crypto_generichash_state *c_state = (crypto_generichash_state *) state_data;
  RN_ARG_BUFFER_NO_CHECK(in)

  RN_CHECK_FAILURE(crypto_generichash_update(c_state, in_data, inlen))

  RN_RETURN_BUFFER(state)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_generichash_final:(NSArray *)state out:(NSArray *) out)
{
  RN_ARG_BUFFER(state, crypto_generichash_statebytes(), ERR_BAD_STATE)
  crypto_generichash_state * c_state = (crypto_generichash_state *) state_data;
  RN_RESULT_BUFFER_NO_CHECK(out)

  RN_CHECK_FAILURE(crypto_generichash_final(c_state, out_data, outlen))

  RN_RETURN_BUFFER(out)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(crypto_kdf_keygen:(NSArray *)key)
{
  RN_RESULT_BUFFER(key, crypto_kdf_KEYBYTES, ERR_BAD_KEY)

  crypto_kdf_keygen(key_data);

  RN_RETURN_BUFFER(key)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_kdf_derive_from_key:(NSArray *)subkey
                              subkey_id:(nonnull NSNumber *) subkey_id
                              ctx:(NSArray *) ctx
                              key:(NSArray *) key)
{
  RN_RESULT_BUFFER_MIN_MAX(subkey, crypto_kdf_BYTES_MIN, crypto_kdf_BYTES_MAX, ERR_BAD_SUBKEY)
  RN_ARG_CONST_BUFFER(ctx, crypto_kdf_CONTEXTBYTES, ERR_BAD_CONTEXT)
  RN_ARG_BUFFER(key, crypto_kdf_KEYBYTES, ERR_BAD_KEY)

  RN_CHECK_FAILURE(crypto_kdf_derive_from_key(subkey_data,
                                              subkeylen,
                                              [subkey_id unsignedLongLongValue],
                                              ctx_data,
                                              key_data))

  RN_RETURN_BUFFER(subkey)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_secretstream_xchacha20poly1305_keygen:(NSArray*)k)
{
  RN_RESULT_BUFFER(k, crypto_secretstream_xchacha20poly1305_KEYBYTES, ERR_BAD_KEY)

  crypto_secretstream_xchacha20poly1305_keygen(k_data);

  RN_RETURN_BUFFER(k)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_secretstream_xchacha20poly1305_init_push:(NSArray *) state
                                                  header:(NSArray *) header
                                                  k:(NSArray *) k)
{
  RN_RESULT_BUFFER(state, crypto_secretstream_xchacha20poly1305_statebytes(), ERR_BAD_STATE)
  RN_ARG_BUFFER(header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, ERR_BAD_HEADER)
  RN_ARG_BUFFER(k, crypto_secretstream_xchacha20poly1305_KEYBYTES, ERR_BAD_KEY)

  crypto_secretstream_xchacha20poly1305_state *c_state = (crypto_secretstream_xchacha20poly1305_state *) state_data;
  RN_CHECK_FAILURE(crypto_secretstream_xchacha20poly1305_init_push(c_state,
                                                                   header_data,
                                                                   k_data))

  RN_RETURN_BUFFERS_2(state, header, headerlen)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_secretstream_xchacha20poly1305_push:(NSArray *) state
                                             c: (NSArray *) c
                                             m: (NSArray *) m
                                             ad: (NSArray *) ad
                                             tag: (NSArray *) tag)
{
  RN_ARG_BUFFER(state, crypto_secretstream_xchacha20poly1305_statebytes(), ERR_BAD_STATE)
  RN_RESULT_BUFFER_NO_CHECK(c)
  RN_ARG_UCONST_BUFFER_NO_CHECK(ad)

  unsigned char _tag = [tag[0] unsignedCharValue];

  unsigned long long mlen_check = clen - crypto_secretstream_xchacha20poly1305_ABYTES;
  RN_ARG_BUFFER(m, mlen_check, ERR_BAD_CIPHERTEXT_LENGTH)

  crypto_secretstream_xchacha20poly1305_state *c_state = (crypto_secretstream_xchacha20poly1305_state *) state_data;
  RN_CHECK_FAILURE(crypto_secretstream_xchacha20poly1305_push(c_state,
                                                              c_data,
                                                              &clen,
                                                              m_data,
                                                              mlen,
                                                              ad_data,
                                                              adlen,
                                                              _tag))

  RN_RETURN_BUFFERS_2(state, c, clen)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_secretstream_xchacha20poly1305_init_pull:(NSArray *) state
                                                  header:(NSArray *) header
                                                  k:(NSArray *) k)
{
  RN_RESULT_BUFFER(state, crypto_secretstream_xchacha20poly1305_statebytes(), ERR_BAD_STATE)
  RN_ARG_UCONST_BUFFER(header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, ERR_BAD_HEADER)
  RN_ARG_UCONST_BUFFER(k, crypto_secretstream_xchacha20poly1305_KEYBYTES, ERR_BAD_KEY)

  crypto_secretstream_xchacha20poly1305_state *c_state = (crypto_secretstream_xchacha20poly1305_state *) state_data;
  RN_CHECK_FAILURE(crypto_secretstream_xchacha20poly1305_init_pull(c_state,
                                                                   header_data,
                                                                   k_data))

  RN_RETURN_BUFFER(state)
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  crypto_secretstream_xchacha20poly1305_pull:(NSArray *) state
                                             m: (NSArray *) m
                                             tag: (NSArray *) tag
                                             c: (NSArray *) c
                                             ad: (NSArray *) ad)
{
  RN_ARG_BUFFER(state, crypto_secretstream_xchacha20poly1305_statebytes(), ERR_BAD_STATE)
  RN_ARG_UCONST_BUFFER_NO_CHECK(c)
  RN_RESULT_BUFFER_NO_CHECK(ad)

  unsigned long long mlen_check = clen - crypto_secretstream_xchacha20poly1305_ABYTES;
  RN_RESULT_BUFFER(m, mlen_check, ERR_BAD_MESSAGE_LENGTH)
  unsigned char tag_p_data[1];
  size_t tag_plen = 1;

  crypto_secretstream_xchacha20poly1305_state *c_state = (crypto_secretstream_xchacha20poly1305_state *) state_data;
  RN_CHECK_FAILURE(crypto_secretstream_xchacha20poly1305_pull(c_state,
                                                              m_data,
                                                              &mlen,
                                                              &tag_p_data[0],
                                                              c_data,
                                                              clen,
                                                              ad_data,
                                                              adlen))

  RN_RETURN_BUFFERS_3(state, tag_p, m, mlen)
}

@end
