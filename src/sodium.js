import { NativeModules } from 'react-native';

const { Libsodium } = NativeModules;
console.log(NativeModules)

let SodiumAPI = {
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
  crypto_kdf_derive_from_key
}

function crypto_generichash_batch(output, batch, key) {
  let batchMap = {}
  for (let i = 0; i < batch.length; i++) {
    batchMap[i.toString()] = batch[i]
  }

  const out = Libsodium.crypto_generichash_batch(output, batchMap, key)
  return new Uint8Array(out)
}

function crypto_aead_xchacha20poly1305_ietf_keygen(k) {
  const key = Libsodium.crypto_aead_xchacha20poly1305_ietf_keygen(k)
  return new Uint8Array(k)
}

function crypto_aead_xchacha20poly1305_ietf_encrypt(...args) {
  const ciphertext = Libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(...Array.from(args, a => Array.from(a)))
  return new Uint8Array(ciphertext)
}

function crypto_aead_xchacha20poly1305_ietf_decrypt(m, nsec, c, ad, npub, k) {
  const plaintext = Libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(...(arguments.map(Array.from)))
  return new Uint8Array(plaintext)
}

function crypto_core_ed25519_scalar_random (r) {
  return new Uint8Array(Libsodium.crypto_core_ed25519_scalar_random(Array.from(r)))
}

function crypto_core_ed25519_add (r, p, q) {
  return new Uint8Array(Libsodium.crypto_core_ed25519_add(...(arguments.map(Array.from))))
}

function crypto_core_ed25519_sub (r, p, q) {
  return new Uint8Array(Libsodium.crypto_core_ed25519_sub(...(arguments.map(Array.from))))
}

function crypto_core_ed25519_from_uniform (p, r) {
  return new Uint8Array(Libsodium.crypto_core_ed25519_from_uniform(...(arguments.map(Array.from))))
}

function crypto_pwhash (out, passwd, salt, opslimit, memlimit, alg) {
  const bufArgs = arguments.slice(0, 3)
  return new Uint8Array(Libsodium.crypto_pwhash(...(bufArgs.map(Array.from)), opslimit, memlimit, alg))
}

function crypto_scalarmult_ed25519 (q, n, p) {
  return new Uint8Array(Libsodium.crypto_scalarmult_ed25519(...(arguments.map(Array.from))))
}

function crypto_scalarmult_ed25519_noclamp (q, n, p) {
  return new Uint8Array(Libsodium.crypto_scalarmult_ed25519_noclamp(...(arguments.map(Array.from))))
}

function crypto_scalarmult_ed25519_base (q, n) {
  return new Uint8Array(Libsodium.crypto_scalarmult_ed25519_base(...(arguments.map(Array.from))))
}

function crypto_scalarmult_ed25519_base_noclamp (q, n) {
  return new Uint8Array(Libsodium.crypto_scalarmult_ed25519_base_noclamp(...(arguments.map(Array.from))))
}

function crypto_generichash_init (state, key, outlen) {
  return new Uint8Array(Libsodium.crypto_generichash_init(...(arguments.map(Array.from))))
}

function crypto_generichash_update (state, input) {
  return new Uint8Array(Libsodium.crypto_generichash_update(...(arguments.map(Array.from))))
}

function crypto_generichash_final (state, out) {
  return new Uint8Array(Libsodium.crypto_generichash_final(...(arguments.map(Array.from))))
}

function crypto_kdf_keygen (...args) { 
  args[0].set(new Uint8Array(Libsodium.crypto_kdf_keygen(...Array.from(args, a => Array.from(a)))))
}

function crypto_kdf_derive_from_key (subkey, subkey_id, ctx, key) {
  return new Uint8Array(Libsodium.crypto_kdf_derive_from_key(...(arguments.map(Array.from))))
}

module.exports = SodiumAPI;
