import * as React from 'react';

console.log('hi')
import { StyleSheet, View, Text } from 'react-native';
import Libsodium from 'react-native-libsodium';

console.log('hi')
try {
  console.log('passed!')
} catch (e) {
  console.log(e)
}

export default function App() {
  const [result, setResult] = React.useState<number | undefined>();

  const c = new Uint8Array(66)
  const m = new Uint8Array(50)
  const key = new Uint8Array(32)
  const nonce = new Uint8Array(24)
  nonce.fill(1)
  key.fill(2)

  Libsodium.crypto_aead_xchacha20poly1305_ietf_keygen(key)
  Libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c, m, new Uint8Array(0), null, nonce, key)
  Libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(m, null, c, new Uint8Array(0), nonce, key)

  const scalar = new Uint8Array(32)
  Libsodium.crypto_core_ed25519_scalar_random(scalar)
  Libsodium.crypto_scalarmult_ed25519_base(key, scalar)
  Libsodium.crypto_core_ed25519_add(key, key, key)

  Libsodium.crypto_scalarmult_ed25519(key, scalar, key)
  Libsodium.crypto_scalarmult_ed25519_noclamp(key, scalar, key)
  Libsodium.crypto_scalarmult_ed25519_base_noclamp(key, scalar)

  const state = new Uint8Array(384)
  Libsodium.crypto_generichash_init(state, key, 24)
  Libsodium.crypto_generichash_update(state, state)
  Libsodium.crypto_generichash_final(state, nonce)

  Libsodium.crypto_kdf_keygen(key)
  Libsodium.crypto_kdf_derive_from_key(nonce, 1, key.subarray(0, 8), key)

  Libsodium.crypto_pwhash(key, nonce, nonce.subarray(0, 16), 2, 67108864, 2)
  console.log(Libsodium)

  return (
    <View style={styles.container}>
      <Text>Result: {result}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
