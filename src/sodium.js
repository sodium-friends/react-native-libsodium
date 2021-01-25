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

function crypto_generichash_batch(out, batch, key) {
  if (!key) key = new Uint8Array(32)

  const state = new Uint8Array(384)
  crypto_generichash_init(state, key, out.byteLength)

  for (let i = 0; i < batch.length; i++) {
    crypto_generichash_update(state, batch[i])
  }

  crypto_generichash_final(state, out)
}

function crypto_aead_xchacha20poly1305_ietf_keygen(k) {
  k.set(new Uint8Array(Libsodium.crypto_aead_xchacha20poly1305_ietf_keygen(k)))
}

function crypto_aead_xchacha20poly1305_ietf_encrypt(...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(...Array.from(args, a => Array.from(a)))))
}

function crypto_aead_xchacha20poly1305_ietf_decrypt(...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(...Array.from(args, a => Array.from(a)))))
}

function crypto_core_ed25519_scalar_random (r) {
  r.set(new Uint8Array(Libsodium.crypto_core_ed25519_scalar_random(Array.from(r))))
}

function crypto_core_ed25519_add (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_core_ed25519_add(...Array.from(args, a => Array.from(a)))))
}

function crypto_core_ed25519_sub (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_core_ed25519_sub(...Array.from(args, a => Array.from(a)))))
}

function crypto_core_ed25519_from_uniform (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_core_ed25519_from_uniform(...Array.from(args, a => Array.from(a)))))
}

function crypto_pwhash (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_pwhash(...Array.from(args.slice(0, 3), a => Array.from(a)))), ...args.slice(3))
}

function crypto_scalarmult_ed25519 (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_scalarmult_ed25519(...Array.from(args, a => Array.from(a)))))
}

function crypto_scalarmult_ed25519_noclamp (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_scalarmult_ed25519_noclamp(...Array.from(args, a => Array.from(a)))))
}

function crypto_scalarmult_ed25519_base (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_scalarmult_ed25519_base(...Array.from(args, a => Array.from(a)))))
}

function crypto_scalarmult_ed25519_base_noclamp (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_scalarmult_ed25519_base_noclamp(...Array.from(args, a => Array.from(a)))))
}

function crypto_generichash_init (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_generichash_init(...Array.from(args.slice(0, 2), a => Array.from(a)), args[2])))
}

function crypto_generichash_update (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_generichash_update(...Array.from(args, a => Array.from(a)))))
}

function crypto_generichash_final (...args) {
  args[1].set(new Uint8Array(Libsodium.crypto_generichash_final(...Array.from(args, a => Array.from(a)))))
}

function crypto_kdf_keygen (...args) { 
  args[0].set(new Uint8Array(Libsodium.crypto_kdf_keygen(...Array.from(args, a => Array.from(a)))))
}

function crypto_kdf_derive_from_key (...args) {
  args[0].set(new Uint8Array(Libsodium.crypto_kdf_derive_from_key(...Array.from(args, a => Array.from(a)))))
}

module.exports = SodiumAPI;
