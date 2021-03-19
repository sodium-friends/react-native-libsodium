#include <jni.h>
#include "sodium.h"


#ifdef __cplusplus
extern "C" {
#endif

/* *****************************************************************************
 * Sodium-specific functions
 * *****************************************************************************
 */
JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_sodium_1init(JNIEnv *jenv, jclass jcls) {
  int result;
  result = (int)sodium_init();
  return (jint)result;
}

JNIEXPORT jstring JNICALL Java_org_libsodium_jni_SodiumJNI_sodium_1version_1string(JNIEnv *jenv, jclass jcls) {
  char *result = (char *)sodium_version_string();
  return (*jenv)->NewStringUTF(jenv, (const char *)result);
}

/* *****************************************************************************
 * Random data generation
 * *****************************************************************************
 */

JNIEXPORT void JNICALL Java_org_libsodium_jni_SodiumJNI_randombytes_1buf(JNIEnv *jenv, jclass jcls, jbyteArray j_buf, jint j_size) {
  unsigned char *buf = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_buf, 0);
  randombytes_buf(buf,(unsigned long long)j_size);
  (*jenv)->ReleaseByteArrayElements(jenv, j_buf, (jbyte *) buf, 0);
}

/* *****************************************************************************
 * Generic hashing - Blake2b
 * *****************************************************************************
 */

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1generichash_1init(JNIEnv *jenv,
                                                                                  jclass clazz,
                                                                                  jbyteArray j_state,
                                                                                  jbyteArray  j_k,
                                                                                  jint  j_klen,
                                                                                  jint j_outlen) {

    unsigned char *state = (crypto_generichash_state *) (*jenv)->GetByteArrayElements(jenv, j_state, 0);
    unsigned char *k = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_k, 0);

    int result = crypto_generichash_init(state, k, j_klen, j_outlen);
    (*jenv)->ReleaseByteArrayElements(jenv, j_state, (jbyte *) state, 0);
    return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1generichash_1update(JNIEnv *jenv,
                                                                                    jclass clazz,
                                                                                    jbyteArray j_state,
                                                                                    jbyteArray  j_in,
                                                                                    jint  j_inlen) {

    unsigned char *state = (crypto_generichash_state *) (*jenv)->GetByteArrayElements(jenv, j_state, 0);
    unsigned char *in = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_in, 0);

    int result = crypto_generichash_update(state, in, j_inlen);
    (*jenv)->ReleaseByteArrayElements(jenv, j_state, (jbyte *) state, 0);
    return (jint)result;
}


JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1generichash_1final(JNIEnv *jenv,
                                                                                    jclass clazz,
                                                                                    jbyteArray j_state,
                                                                                    jbyteArray  j_out,
                                                                                    jint  j_outlen) {

    unsigned char *state = (crypto_generichash_state *) as_unsigned_char_array(jenv, j_state);
    unsigned char *out = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_out, 0);

    int result = crypto_generichash_final(state, out, j_outlen);
    (*jenv)->ReleaseByteArrayElements(jenv, j_out, (jbyte *) out, 0);
    return (jint)result;
}

/* *****************************************************************************
 * Password hashing - Argon2
 * *****************************************************************************
 */

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash(JNIEnv *jenv,
                                                                       jclass jcls,
                                                                       jbyteArray j_out,
                                                                       jlong j_olong,
                                                                       jbyteArray j_p,
                                                                       jlong j_plen,
                                                                       jbyteArray j_salt,
                                                                       jlong j_opslimit,
                                                                       jlong jmemlimit,
                                                                       jint j_algo) {

  const char *password = (const char *) (*jenv)->GetByteArrayElements(jenv, j_p, 0);
  unsigned char *salt = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_salt, 0);
  unsigned char *out = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_out, 0);

  int result = crypto_pwhash(out, (unsigned long long) j_olong, password, (unsigned long long) j_plen, salt, (unsigned long long) j_opslimit, (unsigned long long) jmemlimit, (unsigned int) j_algo);

  (*jenv)->ReleaseByteArrayElements(jenv, j_p, (jbyte *) password, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_salt, (jbyte *) salt, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_out, (jbyte *) out, 0);
  return (jint) result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1salt_1bytes(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_SALTBYTES;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1opslimit_1moderate(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_OPSLIMIT_MODERATE;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1opslimit_1min(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_OPSLIMIT_MIN;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1opslimit_1max(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_OPSLIMIT_MAX;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1memlimit_1moderate(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_MEMLIMIT_MODERATE;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1memlimit_1min(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_MEMLIMIT_MIN;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1memlimit_1max(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_MEMLIMIT_MAX;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1algo_1default(JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_ALG_DEFAULT;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1algo_1argon2i13 (JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_ALG_ARGON2I13;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1pwhash_1algo_1argon2id13 (JNIEnv *jenv, jclass jcls) {
  return (jint) crypto_pwhash_ALG_ARGON2ID13;
}

/* *****************************************************************************
 * Public-key cryptography - authenticated encryption
 * *****************************************************************************
 */

// use only for copying values, returning values here from crypto won't work
unsigned char* as_unsigned_char_array(JNIEnv *jenv, jbyteArray array) {
    if (array == NULL) {
        return NULL;
    }
    int len = (*jenv)->GetArrayLength (jenv, array);
    unsigned char* buf = malloc(len);
    (*jenv)->GetByteArrayRegion (jenv, array, 0, len, (jbyte*)(buf));
    return buf;
}


JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1aead_1xchacha20poly1305_1ietf_1encrypt(JNIEnv *jenv,
                                                                                jclass clazz,
                                                                                jbyteArray j_c,
                                                                                jintArray  j_clen,
                                                                                jbyteArray j_m,
                                                                                jint j_mlen,
                                                                                jbyteArray j_ad,
                                                                                jint j_adlen,
                                                                                jbyteArray j_nsec,
                                                                                jbyteArray j_npub,
                                                                                jbyteArray j_k) {

    unsigned char *c = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_c, 0);
    unsigned char *m = as_unsigned_char_array(jenv, j_m);
    unsigned char *npub = as_unsigned_char_array(jenv, j_npub);
    unsigned char *ad = as_unsigned_char_array(jenv, j_ad);
    unsigned char *nsec = as_unsigned_char_array(jenv, j_nsec);
    unsigned char *k = as_unsigned_char_array(jenv, j_k);

    int result = crypto_aead_xchacha20poly1305_ietf_encrypt(c, j_clen, m, j_mlen, ad, j_adlen, nsec, npub, k);
    (*jenv)->ReleaseByteArrayElements(jenv, j_c, (jbyte *) c, 0);
    return (jint)result;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1aead_1xchacha20poly1305_1ietf_1decrypt(JNIEnv *jenv,
                                                                                jclass clazz,
                                                                                jbyteArray j_m,
                                                                                jintArray j_mlen_p,
                                                                                jbyteArray j_nsec,
                                                                                jbyteArray j_c,
                                                                                jint j_clen,
                                                                                jbyteArray j_ad,
                                                                                jint j_adlen,
                                                                                jbyteArray j_npub,
                                                                                jbyteArray j_k) {
    unsigned char *c = as_unsigned_char_array(jenv, j_c);
    unsigned char *m = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_m, 0);
    unsigned char *npub = as_unsigned_char_array(jenv, j_npub);
    unsigned char *ad = as_unsigned_char_array(jenv, j_ad);
    unsigned char *nsec = as_unsigned_char_array(jenv, j_nsec);
    unsigned char *k = as_unsigned_char_array(jenv, j_k);

    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(m, j_mlen_p, nsec, c, j_clen, ad, j_adlen, npub, k);
    (*jenv)->ReleaseByteArrayElements(jenv, j_m, (jbyte *) m, 0);
    return (jint)result;
}

JNIEXPORT jchar JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1aead_1xchacha20poly1305_1ietf_1keygen(JNIEnv *jenv,
                                                                               jclass clazz,
                                                                               jbyteArray j_k) {
  unsigned char *k = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_k, 0);
  crypto_aead_xchacha20poly1305_ietf_keygen(k);
  (*jenv)->ReleaseByteArrayElements(jenv, j_k, (jbyte *) k, 0);
  return k;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1aead_1chacha20poly1305_1IETF_1ABYTES(JNIEnv *env,
                                                                              jclass clazz) {
  return (jint) crypto_aead_chacha20poly1305_IETF_ABYTES;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1aead_1xchacha20poly1305_1IETF_1KEYBYTES(JNIEnv *env,
                                                                                 jclass clazz) {
  return (jint)crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1aead_1xchacha20poly1305_1IETF_1NPUBBYTES(JNIEnv *env,
                                                                                  jclass clazz) {
  return (jint)crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1aead_1xchacha20poly1305_1IETF_1NSECBYTES(JNIEnv *env,
                                                                                  jclass clazz) {
  return (jint)crypto_aead_xchacha20poly1305_IETF_NSECBYTES;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_base64_1variant_1ORIGINAL(JNIEnv *env, jclass clazz) {
    return (jint)sodium_base64_VARIANT_ORIGINAL;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_base64_1variant_1VARIANT_1ORIGINAL_1NO_1PADDING(JNIEnv *env,
                                                                                 jclass clazz) {
    return (jint)sodium_base64_VARIANT_ORIGINAL_NO_PADDING;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_base64_1variant_1VARIANT_1URLSAFE(JNIEnv *env, jclass clazz) {
    return (jint)sodium_base64_VARIANT_URLSAFE;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_base64_1variant_1VARIANT_1URLSAFE_1NO_1PADDING(JNIEnv *env,
                                                                                jclass clazz) {
    return (jint)sodium_base64_VARIANT_URLSAFE_NO_PADDING;
}

/* *****************************************************************************
 * Secret-key cryptography - Authemticated encryption
 * *****************************************************************************
 */

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1secretbox_1easy(JNIEnv *jenv,
                                                                                  jclass clazz,
                                                                                  jbyteArray  j_c,
                                                                                  jbyteArray  j_m,
                                                                                  jint  j_mlen,
                                                                                  jbyteArray  j_n,
                                                                                  jint  j_k) {

    unsigned char *c = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_c, 0);
    unsigned char *m = as_unsigned_char_array(jenv, j_m);
    unsigned char *n = as_unsigned_char_array(jenv, j_n);
    unsigned char *k = as_unsigned_char_array(jenv, j_k);

    int result = crypto_secretbox_easy(state, k, j_klen, j_outlen);
    (*jenv)->ReleaseByteArrayElements(jenv, j_c, (jbyte *) c, 0);
    return (jint)result;
}

/* *****************************************************************************
 * Secret-key cryptography - stream encryption
 * *****************************************************************************
 */

JNIEXPORT jchar JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1keygen(JNIEnv *jenv,
                                                                                 jclass clazz,
                                                                                 jbyteArray j_k) {
  unsigned char *k = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_k, 0);
  crypto_secretstream_xchacha20poly1305_keygen(k);
  (*jenv)->ReleaseByteArrayElements(jenv, j_k, (jbyte *) k, 0);
  return k;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1init_1pull(JNIEnv *jenv,
                                                                                                            jclass clazz,
                                                                                                            jbyteArray j_state,
                                                                                                            jbyteArray  j_header,
                                                                                                            jbyteArray j_k) {

    unsigned char *state = (crypto_secretstream_xchacha20poly1305_state *) (*jenv)->GetByteArrayElements(jenv, j_state, 0);
    unsigned char *header = as_unsigned_char_array(jenv, j_header);
    unsigned char *k = as_unsigned_char_array(jenv, j_k);

    int result = crypto_secretstream_xchacha20poly1305_init_pull(state, header, k);
    (*jenv)->ReleaseByteArrayElements(jenv, j_state, (jbyte *) state, 0);
    return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1init_1push(JNIEnv *jenv,
                                                                                                            jclass clazz,
                                                                                                            jbyteArray j_state,
                                                                                                            jbyteArray  j_header,
                                                                                                            jbyteArray j_k) {

    unsigned char *state = (crypto_secretstream_xchacha20poly1305_state *) (*jenv)->GetByteArrayElements(jenv, j_state, 0);
    unsigned char *header = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_header, 0);
    unsigned char *k = as_unsigned_char_array(jenv, j_k);

    int result = crypto_secretstream_xchacha20poly1305_init_push(state, header, k);
    (*jenv)->ReleaseByteArrayElements(jenv, j_state, (jbyte *) state, 0);
    (*jenv)->ReleaseByteArrayElements(jenv, j_header, (jbyte *) state, 0);
    return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1push(JNIEnv *jenv,
                                                                                                      jclass clazz,
                                                                                                      jbyteArray j_state,
                                                                                                      jbyteArray  j_c,
                                                                                                      jintArray  j_clen_p,
                                                                                                      jbyteArray  j_m,
                                                                                                      jint  j_mlen,
                                                                                                      jbyteArray  j_ad,
                                                                                                      jint  j_adlen,
                                                                                                      jint j_tag) {

    unsigned char *state = (crypto_secretstream_xchacha20poly1305_state *) (*jenv)->GetByteArrayElements(jenv, j_state, 0);
    unsigned char *c = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_c, 0);
    unsigned char *m = as_unsigned_char_array(jenv, j_m);
    unsigned char *ad = as_unsigned_char_array(jenv, j_ad);

    int result = crypto_secretstream_xchacha20poly1305_push(state, c, j_clen_p, m, j_mlen, ad, j_adlen, j_tag);
    (*jenv)->ReleaseByteArrayElements(jenv, j_state, (jbyte *) state, 0);
    (*jenv)->ReleaseByteArrayElements(jenv, j_c, (jbyte *) c, 0);
    return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1pull(JNIEnv *jenv,
                                                                                                      jclass clazz,
                                                                                                      jbyteArray j_state,
                                                                                                      jbyteArray  j_m,
                                                                                                      jintArray  j_mlen_p,
                                                                                                      jbyteArray  j_tag_p,
                                                                                                      jbyteArray  j_c,
                                                                                                      jint  j_clen,
                                                                                                      jbyteArray  j_ad,
                                                                                                      jint  j_adlen) {

    unsigned char *state = (crypto_secretstream_xchacha20poly1305_state *) (*jenv)->GetByteArrayElements(jenv, j_state, 0);
    unsigned char *m = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_m, 0);
    unsigned char *tag = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_tag, 0);
    unsigned char *c = as_unsigned_char_array(jenv, j_c);
    unsigned char *ad = as_unsigned_char_array(jenv, j_ad);

    int result = crypto_secretstream_xchacha20poly1305_push(state, m, j_mlen_p, tag, c, j_clen, ad, j_adlen);
    (*jenv)->ReleaseByteArrayElements(jenv, j_state, (jbyte *) state, 0);
    (*jenv)->ReleaseByteArrayElements(jenv, j_m, (jbyte *) m, 0);
    (*jenv)->ReleaseByteArrayElements(jenv, j_tag, (jbyte *) tag, 0);
    return (jint)result;
}

/* *****************************************************************************
 * Secret-key cryptography - stream encryption
 * *****************************************************************************
 */

JNIEXPORT jchar JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1kdf_1keygen(JNIEnv *jenv,
                                                     jclass clazz,
                                                     jbyteArray j_k) {

  unsigned char *k = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_k, 0);
  crypto_kdf_keygen(k);
  (*jenv)->ReleaseByteArrayElements(jenv, j_k, (jbyte *) k, 0);
  return k;
}


JNIEXPORT jchar JNICALL
Java_org_libsodium_jni_SodiumJNI_crypto_1kdf_1derive_1from_1key(JNIEnv *jenv,
                                                     jclass clazz,
                                                     jbyteArray j_subkey,
                                                     jint j_subkey_id,
                                                     jbyteArray j_ctx,
                                                     jbyteArray j_k) {

  unsigned char *subkey = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_subkey, 0);
  unsigned char *ctx = as_unsigned_char_array(jenv, j_ctx);
  unsigned char *k = as_unsigned_char_array(jenv, j_k);
  int result = crypto_kdf_derive_from_key(subkey, j_subkey_id, ctx, k);
  (*jenv)->ReleaseByteArrayElements(jenv, j_subkey, (jbyte *) subkey, 0);
  return (jint)result;
}

/* *****************************************************************************
 * Advanced - Ed25519 arithmetic
 * *****************************************************************************
 */

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1bytes(JNIEnv *jenv, jclass jcls) {
  return (jint)crypto_core_ed25519_BYTES;
}
 
JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1uniformbytes(JNIEnv *jenv, jclass jcls) {
  return (jint)crypto_core_ed25519_UNIFORMBYTES;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1scalarbytes(JNIEnv *jenv, jclass jcls) {
  return (jint)crypto_core_ed25519_SCALARBYTES;
}
 
JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1nonreducedscalarbytes(JNIEnv *jenv, jclass jcls) {
  return (jint)crypto_core_ed25519_NONREDUCEDSCALARBYTES;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1scalar_1random(JNIEnv *jenv,
                                                                                              jclass jcls,
                                                                                              jbyteArray j_r) {

  unsigned char *r = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_r, 0);
  int result = (int)crypto_core_ed25519_scalar_random(r);
  (*jenv)->ReleaseByteArrayElements(jenv, j_r, (jbyte *) r, 0);
  return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1add(JNIEnv *jenv,
                                                                                   jclass jcls,
                                                                                   jbyteArray j_r,
                                                                                   jbyteArray j_p,
                                                                                   jbyteArray j_q) {

  unsigned char *r = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_r, 0);
  unsigned char *p = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_p, 0);
  unsigned char *q = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_q, 0);
  int result = (int)crypto_core_ed25519_add(r, p, q);
  (*jenv)->ReleaseByteArrayElements(jenv, j_r, (jbyte *) r, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_p, (jbyte *) p, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_q, (jbyte *) q, 0);
  return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1sub(JNIEnv *jenv,
                                                                                   jclass jcls,
                                                                                   jbyteArray j_r,
                                                                                   jbyteArray j_p,
                                                                                   jbyteArray j_q) {

  unsigned char *r = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_r, 0);
  unsigned char *p = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_p, 0);
  unsigned char *q = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_q, 0);
  int result = (int)crypto_core_ed25519_sub(r, p, q);
  (*jenv)->ReleaseByteArrayElements(jenv, j_r, (jbyte *) r, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_p, (jbyte *) p, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_q, (jbyte *) q, 0);
  return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1core_1ed25519_1from_1uniform(JNIEnv *jenv,
                                                                                             jclass jcls,
                                                                                             jbyteArray j_p,
                                                                                             jbyteArray j_r) {

  unsigned char *p = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_p, 0);
  unsigned char *r = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_r, 0);
  int result = (int)crypto_core_ed25519_sub(p, r);
  (*jenv)->ReleaseByteArrayElements(jenv, j_p, (jbyte *) p, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_r, (jbyte *) r, 0);
  return (jint)result;
}

/* *****************************************************************************
 * Advanced - Ed25519 Point * scalar multiplication
 * *****************************************************************************
 */

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1scalarmult_1ed25519_1bytes(JNIEnv *jenv, jclass jcls) {
  return (jint)crypto_scalarmult_ed25519_BYTES;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1scalarmult_1ed25519_1scalarbytes(JNIEnv *jenv, jclass jcls) {
  return (jint)crypto_scalarmult_ed25519_SCALARBYTES;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1scalarmult_1ed25519_1base(JNIEnv *jenv,
                                                                                          jclass jcls,
                                                                                          jbyteArray j_q,
                                                                                          jbyteArray j_n) {

  unsigned char *q = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_q, 0);
  unsigned char *n = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_n, 0);
  int result = (int)crypto_scalarmult_ed25519_base(q, n);
  (*jenv)->ReleaseByteArrayElements(jenv, j_q, (jbyte *) q, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_n, (jbyte *) n, 0);
  return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1scalarmult_1ed25519(JNIEnv *jenv,
                                                                                    jclass jcls,
                                                                                    jbyteArray j_q,
                                                                                    jbyteArray j_n,
                                                                                    jbyteArray j_p) {

  unsigned char *q = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_q, 0);
  unsigned char *n = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_n, 0);
  unsigned char *p = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_p, 0);
  int result = (int)crypto_scalarmult_ed25519(q, n, p);
  (*jenv)->ReleaseByteArrayElements(jenv, j_q, (jbyte *) q, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_n, (jbyte *) n, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_p, (jbyte *) p, 0);
  return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1scalarmult_1ed25519_1base_noclamp(JNIEnv *jenv,
                                                                                                  jclass jcls,
                                                                                                  jbyteArray j_q,
                                                                                                  jbyteArray j_n) {

  unsigned char *q = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_q, 0);
  unsigned char *n = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_n, 0);
  int result = (int)crypto_scalarmult_ed25519_base(q, n);
  (*jenv)->ReleaseByteArrayElements(jenv, j_q, (jbyte *) q, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_n, (jbyte *) n, 0);
  return (jint)result;
}

JNIEXPORT jint JNICALL Java_org_libsodium_jni_SodiumJNI_crypto_1scalarmult_1ed25519_noclamp(JNIEnv *jenv,
                                                                                            jclass jcls,
                                                                                            jbyteArray j_q,
                                                                                            jbyteArray j_n,
                                                                                            jbyteArray j_p) {

  unsigned char *q = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_q, 0);
  unsigned char *n = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_n, 0);
  unsigned char *p = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_p, 0);
  int result = (int)crypto_scalarmult_ed25519(q, n, p);
  (*jenv)->ReleaseByteArrayElements(jenv, j_q, (jbyte *) q, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_n, (jbyte *) n, 0);
  (*jenv)->ReleaseByteArrayElements(jenv, j_p, (jbyte *) p, 0);
  return (jint)result;
}

/* *****************************************************************************
 * Sodium helpers
 * *****************************************************************************
 */

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_sodium_1base642bin(JNIEnv *jenv, jclass clazz, jbyteArray j_bin,
                                                    jint j_bin_maxlen, jbyteArray j_b64, jint j_b64_len,
                                                    jbyteArray j_ignore, jintArray j_bin_len,
                                                    jbyteArray j_b64_end, jint j_variant) {

    unsigned char *bin = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_bin, 0);
    jint *len = (*jenv)->GetIntArrayElements(jenv, j_bin_len, 0);
    unsigned char *b64 = as_unsigned_char_array(jenv, j_b64);
    unsigned char *ignore = as_unsigned_char_array(jenv, j_ignore);
    void *memory = malloc(sizeof(int));
    int *ptr = (int *)memory;

    int result = sodium_base642bin(bin, j_bin_maxlen, b64, j_b64_len, ignore,
                                   ptr, j_b64_end, j_variant);
    (*jenv)->ReleaseByteArrayElements(jenv, j_bin, (jbyte *) bin, 0);
    len[0] = *ptr;
    (*jenv)->ReleaseIntArrayElements(jenv, j_bin_len, len, 0);
    free(memory);
    return (jint)result;
}

JNIEXPORT jchar JNICALL
Java_org_libsodium_jni_SodiumJNI_sodium_1bin2hex(JNIEnv *jenv, jclass clazz, jbyteArray j_hex,
                                                 jint j_hex_maxlen, jbyteArray j_bin, jint j_bin_len) {

    unsigned char *hex = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_hex, 0);
    unsigned char *bin = as_unsigned_char_array(jenv, j_bin);

    int result = sodium_bin2hex(hex, j_hex_maxlen, bin, j_bin_len);
    (*jenv)->ReleaseByteArrayElements(jenv, j_hex, (jbyte *) hex, 0);
    return (jint)result;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_sodium_1hex2bin(JNIEnv *jenv, jclass clazz, jbyteArray j_bin,
                                                 jint j_bin_maxlen, jbyteArray j_hex, jint j_hex_len,
                                                 jbyteArray j_ignore, jintArray j_bin_len,
                                                 jbyteArray j_hex_end) {

    unsigned char *bin = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_bin, 0);
    jint *len = (*jenv)->GetIntArrayElements(jenv, j_bin_len, 0);
    unsigned char *hex = as_unsigned_char_array(jenv, j_hex);
    unsigned char *ignore = as_unsigned_char_array(jenv, j_ignore);
    void *memory = malloc(sizeof(int));
    int *ptr = (int *)memory;

    int result = sodium_hex2bin(bin, j_bin_maxlen, hex, j_hex_len, ignore, ptr, j_hex_end);
    (*jenv)->ReleaseByteArrayElements(jenv, j_bin, (jbyte *) bin, 0);
    len[0] = *ptr;
    (*jenv)->ReleaseIntArrayElements(jenv, j_bin_len, len, 0);
    free(memory);
    return (jint)result;
}

JNIEXPORT jchar JNICALL
Java_org_libsodium_jni_SodiumJNI_sodium_1bin2base64(JNIEnv *jenv, jclass clazz, jbyteArray j_b64,
                                                    jint j_b64_maxlen, jbyteArray j_bin, jint j_bin_len,
                                                    jint j_variant) {

    unsigned char *b64 = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_b64, 0);
    unsigned char *bin = as_unsigned_char_array(jenv, j_bin);

    int result = sodium_bin2base64(b64, j_b64_maxlen, bin, j_bin_len, j_variant);
    (*jenv)->ReleaseByteArrayElements(jenv, j_b64, (jbyte *) b64, 0);
    return (jint)result;
}

JNIEXPORT jint JNICALL
Java_org_libsodium_jni_SodiumJNI_sodium_1base64_1encoded_1len(JNIEnv *jenv, jclass clazz,
                                                              jint j_bin_len, jint j_variant) {
    return (jint) sodium_base64_encoded_len(j_bin_len, j_variant);
}

#ifdef __cplusplus
}
#endif
