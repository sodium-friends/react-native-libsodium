/**
 * @providesModule Sodium
 * @flow
 */

import { NativeModules } from 'react-native';
import bint from 'bint8array';

const { Sodium } = NativeModules;
// console.log(NativeModules)

const constants = Object.fromEntries(Object.entries(Sodium.getConstants()).map(
  ([k, v]) => {
    if (k.slice(0, 42) == '_crypto_secretstream_xchacha20poly1305_TAG') {
      return [k.slice(1), new Uint8Array([v])]
    }
    return [k, v]
  }))

let SodiumAPI = {
  ...constants,
  crypto_generichash_batch,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_core_ed25519_scalar_random,
  crypto_core_ed25519_add,
  crypto_core_ed25519_sub,
  crypto_core_ed25519_from_uniform,
  crypto_pwhash,
  crypto_pwhash_async,
  crypto_scalarmult_ed25519,
  crypto_scalarmult_ed25519_noclamp,
  crypto_scalarmult_ed25519_base,
  crypto_scalarmult_ed25519_base_noclamp,
  crypto_generichash_init,
  crypto_generichash_update,
  crypto_generichash_final,
  crypto_kdf_keygen,
  crypto_kdf_derive_from_key,
  crypto_secretstream_xchacha20poly1305_keygen,
  crypto_secretstream_xchacha20poly1305_init_push,
  crypto_secretstream_xchacha20poly1305_push,
  crypto_secretstream_xchacha20poly1305_init_pull,
  crypto_secretstream_xchacha20poly1305_pull,
  crypto_secretbox_easy,
  randombytes_buf,
  sodium_memcmp,
  sodium_memzero,
  sodium_free,
  sodium_malloc
}

function crypto_secretbox_easy(...args) {
  const res = new Uint8Array(Sodium.crypto_secretbox_easy(...Array.from(args, mapArgs)))
  args[0].set(res)
}

function crypto_generichash_batch(out, batch, key) {
  if (!key) key = new Uint8Array(0)

  const state = new Uint8Array(384)
  crypto_generichash_init(state, key, out.byteLength)

  for (let i = 0; i < batch.length; i++) {
    crypto_generichash_update(state, batch[i])
  }

  crypto_generichash_final(state, out)
}

function crypto_aead_xchacha20poly1305_ietf_keygen(k) {
  k.set(new Uint8Array(Sodium.crypto_aead_xchacha20poly1305_ietf_keygen(Array.from(k))))
}

function randombytes_buf(buf) {
  buf.set(new Uint8Array(Sodium.randombytes_buf(Array.from(buf))))
}

function crypto_aead_xchacha20poly1305_ietf_encrypt(...args) {
  const nativeResult = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_aead_xchacha20poly1305_ietf_encrypt execeution failed: ' + nativeResult + '.')
  const res = new Uint8Array(nativeResult)
  args[0].set(res)
  return res.byteLength
}

function crypto_aead_xchacha20poly1305_ietf_decrypt(...args) {
  const nativeResult = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_aead_xchacha20poly1305_ietf_decrypt execeution failed: ' + nativeResult + '.')
  const res = new Uint8Array(nativeResult)
  args[0].set(res)
  return res.byteLength
}

function crypto_core_ed25519_scalar_random (r) {
  r.set(new Uint8Array(Sodium.crypto_core_ed25519_scalar_random(Array.from(r))))
}

function crypto_core_ed25519_add (...args) {
  const nativeResult = Sodium.crypto_core_ed25519_add(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_core_ed25519_add execution faile: ' + nativeResult + 'd')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_core_ed25519_sub (...args) {
  const nativeResult = Sodium.crypto_core_ed25519_sub(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_core_ed25519_sub execution faile: ' + nativeResult + 'd')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_core_ed25519_from_uniform (...args) {
  const nativeResult = Sodium.crypto_core_ed25519_from_uniform(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_core_ed25519_from_uniform execution faile: ' + nativeResult + 'd')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_pwhash (...args) {
  const nativeResult = Sodium.crypto_pwhash(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_pwhash execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

async function crypto_pwhash_async (...args) {
  let nativeResult
  try {
    nativeResult = await Sodium.crypto_pwhash(...Array.from(args, mapArgs))
  } catch (e) {
    throw e
  }

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519 (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_scalarmult_ed25519 execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519_noclamp (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519_noclamp(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_scalarmult_ed25519_noclamp execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519_base (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519_base(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_scalarmult_ed25519_base execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519_base_noclamp (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519_base_noclamp(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_scalarmult_ed25519_base_noclamp execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_secretstream_xchacha20poly1305_keygen (...args) {
  args[0].set(new Uint8Array(Sodium.crypto_secretstream_xchacha20poly1305_keygen(...Array.from(args, mapArgs))))
}

function crypto_secretstream_xchacha20poly1305_init_push (...args) {
  const nativeResult = Sodium.crypto_secretstream_xchacha20poly1305_init_push(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_secretstream_xchacha20poly1305_init_push execution failed: ' + nativeResult + '.')

  const resultBuf = new Uint8Array(nativeResult)
  args[0].set(resultBuf.subarray(0, constants.crypto_secretstream_xchacha20poly1305_STATEBYTES))
  args[1].set(resultBuf.subarray(constants.crypto_secretstream_xchacha20poly1305_STATEBYTES))
}

function crypto_secretstream_xchacha20poly1305_push (...args) {
  const nativeResult = Sodium.crypto_secretstream_xchacha20poly1305_push(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_secretstream_xchacha20poly1305_push execution failed: ' + nativeResult + '.')

  const resultBuf = new Uint8Array(nativeResult)
  args[0].set(resultBuf.subarray(0, constants.crypto_secretstream_xchacha20poly1305_STATEBYTES))
  args[1].set(resultBuf.subarray(constants.crypto_secretstream_xchacha20poly1305_STATEBYTES))
}

function crypto_secretstream_xchacha20poly1305_init_pull (...args) {
  const nativeResult = Sodium.crypto_secretstream_xchacha20poly1305_init_pull(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_secretstream_xchacha20poly1305_init_pull execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_secretstream_xchacha20poly1305_pull (...args) {
  const nativeResult = Sodium.crypto_secretstream_xchacha20poly1305_pull(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_secretstream_xchacha20poly1305_pull execution failed: ' + nativeResult + '.')

  const resultBuf = new Uint8Array(nativeResult)
  args[0].set(resultBuf.subarray(0, constants.crypto_secretstream_xchacha20poly1305_STATEBYTES))    // state
  args[2][0] = resultBuf[constants.crypto_secretstream_xchacha20poly1305_STATEBYTES]                // tag
  args[1].set(resultBuf.subarray(constants.crypto_secretstream_xchacha20poly1305_STATEBYTES + 1))   // message
}

function crypto_generichash_init (...args) {
  const nativeResult = Sodium.crypto_generichash_init(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_generichash_init execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_generichash_update (...args) {
  const nativeResult = Sodium.crypto_generichash_update(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_generichash_update execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_generichash_final (...args) {
  const nativeResult = Sodium.crypto_generichash_final(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_generichash_final execution failed: ' + nativeResult + '.')

  args[1].set(new Uint8Array(nativeResult))
}

function crypto_kdf_keygen (...args) {
  args[0].set(new Uint8Array(Sodium.crypto_kdf_keygen(...Array.from(args, mapArgs))))
}

function crypto_kdf_derive_from_key (...args) {
  const nativeResult = Sodium.crypto_kdf_derive_from_key(...Array.from(args, mapArgs))
  if (typeof nativeResult === 'string') throw new Error('crypto_kdf_derive_from_key execution failed: ' + nativeResult + '.')

  args[0].set(new Uint8Array(nativeResult))
}

function sodium_memcmp (a, b) {
  return vn(a, 0, b, 0, a.byteLength) === 0 && a.byteLength === b.byteLength
}

function sodium_malloc (n) {
  return new Uint8Array(n)
}

function sodium_free (n) {
  sodium_memzero(n)
}

function sodium_memzero (arr) {
  arr.fill(0)
}

module.exports = SodiumAPI;

function mapArgs (arg) {
  if (arg == null) return new Array(0)
  if (typeof arg === 'number') return arg
  return Array.from(arg)
}

// constant time compare
function vn (x, xi, y, yi, n) {
  var d = 0
  for (let i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i]
  return (1 & ((d - 1) >>> 8)) - 1
}
