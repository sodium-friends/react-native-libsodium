<<<<<<< HEAD
import Libsodium from './src/sodium.js';

export default Libsodium;
=======
/**
 * @providesModule Sodium
 * @flow
 */

import { NativeModules } from 'react-native';

const { Sodium } = NativeModules;
// console.log(NativeModules)

let SodiumAPI = {
  ...Sodium.getConstants(),
  crypto_generichash_batch,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_core_ed25519_scalar_random,
  crypto_core_ed25519_add,
  crypto_core_ed25519_sub,
  crypto_core_ed25519_from_uniform,
  crypto_pwhash,
  crypto_scalarmult_ed25519,
  crypto_scalarmult_ed25519_noclamp,
  crypto_scalarmult_ed25519_base,
  crypto_scalarmult_ed25519_base_noclamp,
  crypto_generichash_init,
  crypto_generichash_update,
  crypto_generichash_final,
  crypto_kdf_keygen,
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy
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

function crypto_aead_xchacha20poly1305_ietf_encrypt(...args) {
  const nativeResult = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_aead_xchacha20poly1305_ietf_encrypt execeution failed.')
  const res = new Uint8Array(nativeResult)
  args[0].set(res)
  return res.byteLength
}

function crypto_aead_xchacha20poly1305_ietf_decrypt(...args) {
  const nativeResult = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_aead_xchacha20poly1305_ietf_decrypt execeution failed.')
  const res = new Uint8Array(nativeResult)
  args[0].set(res)
  return res.byteLength
}

function crypto_core_ed25519_scalar_random (r) {
  r.set(new Uint8Array(Sodium.crypto_core_ed25519_scalar_random(Array.from(r))))
}

function crypto_core_ed25519_add (...args) {
  const nativeResult = Sodium.crypto_core_ed25519_add(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_core_ed25519_add execution failed')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_core_ed25519_sub (...args) {
  const nativeResult = Sodium.crypto_core_ed25519_sub(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_core_ed25519_sub execution failed')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_core_ed25519_from_uniform (...args) {
  const nativeResult = Sodium.crypto_core_ed25519_from_uniform(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_core_ed25519_from_uniform execution failed')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_pwhash (...args) {
  const nativeResult = Sodium.crypto_pwhash(...Array.from(args.slice(0, 3), mapArgs), ...args.slice(3))
  if (nativeResult === 'FAILURE') throw new Error('crypto_pwhash execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519 (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_scalarmult_ed25519 execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519_noclamp (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519_noclamp(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_scalarmult_ed25519_noclamp execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519_base (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519_base(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_scalarmult_ed25519_base execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_scalarmult_ed25519_base_noclamp (...args) {
  const nativeResult = Sodium.crypto_scalarmult_ed25519_base_noclamp(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_scalarmult_ed25519_base_noclamp execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_generichash_init (...args) {
  const nativeResult = Sodium.crypto_generichash_init(...Array.from(args.slice(0, 2), mapArgs), args[2])
  if (nativeResult === 'FAILURE') throw new Error('crypto_generichash_init execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_generichash_update (...args) {
  const nativeResult = Sodium.crypto_generichash_update(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_generichash_update execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

function crypto_generichash_final (...args) {
  const nativeResult = Sodium.crypto_generichash_final(...Array.from(args, mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_generichash_final execution failed.')

  args[1].set(new Uint8Array(nativeResult))
}

function crypto_kdf_keygen (...args) { 
  args[0].set(new Uint8Array(Sodium.crypto_kdf_keygen(...Array.from(args, mapArgs))))
}

function crypto_kdf_derive_from_key (...args) {
  const nativeResult = Sodium.crypto_kdf_derive_from_key(mapArgs(args[0]), args[1], ...Array.from(args.slice(2), mapArgs))
  if (nativeResult === 'FAILURE') throw new Error('crypto_kdf_derive_from_key execution failed.')

  args[0].set(new Uint8Array(nativeResult))
}

module.exports = SodiumAPI;

function mapArgs (arg) {
  if (arg == null) return new Array(0)
  return Array.from(arg)
}
>>>>>>> 6ea05c9 (update to work as npm module)
