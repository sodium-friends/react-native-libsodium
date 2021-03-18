# react-native-libsodium

A port of Frank Denis' [libsodium](https://libsodium.gitbook.io/doc/) cryptogrpahy library for React Native. This library is intended to eb a drop in replacement for preexisting [NodeJs and JavaScript ports](https://sodium-friends.github.io/docs/docs/getstarted). 

Only a subset of the functions have been exposed, however, contributions are most welcome. You can read our [guide](./CONTRIBUTING.md) for clear information on how to go about exposing new methods.

## Installation

```sh
npm install react-native-libsodium
```

## Usage

```js
import sodium from "react-native-libsodium";

const key = sodium_malloc(sodium.crypto_kdf_KEYBYTES)
const subkey = sodium_malloc(sodium.crypto_kdf_BYTES_MAX)
const ctx = sodium_malloc(sodium.crypto_kdf_CONTEXTBYTES

sodium.crypto_kdf_keygen(key);
sodium.crypto_kdf_derive_from_key(subkey, 1, ctx, key)
```

## API

Full API documentation for each method may be found under the links in each section.

#### `crypto_aead_xchacha20poly1305`

[Authenticated encryption](https://sodium-friends.github.io/docs/docs/aead)

#### Methods
```
  crypto_aead_xchacha20poly1305_ietf_keygen
  crypto_aead_xchacha20poly1305_ietf_encrypt
  crypto_aead_xchacha20poly1305_ietf_decrypt
```

#### Constants
```
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  crypto_aead_xchacha20poly1305_ietf_ABYTES
```

### Curve arithemetic

[Ed25519 arithmetic](https://sodium-friends.github.io/docs/docs/finitefieldarithmetic)

#### Methods
```
  crypto_core_ed25519_scalar_random
  crypto_core_ed25519_add
  crypto_core_ed25519_sub
  crypto_core_ed25519_from_uniform

  crypto_scalarmult_ed25519
  crypto_scalarmult_ed25519_base
```

Clamping involves clearing the lowest 3 bits of the result, ensuring the result lies on the main subgroup of the curve. However, this breaks point inversion which is undesireable for some protcocols. See [here](https://www.jcraige.com/an-explainer-on-ed25519-clamping) for a more detailed explanation.

```
  crypto_scalarmult_ed25519_noclamp
  crypto_scalarmult_ed25519_base_noclamp
```

#### Constants
```
  crypto_core_ed25519_SCALARBYTES
  crypto_core_ed25519_BYTES
  crypto_core_ed25519_UNIFORMBYTES

  crypto_scalarmult_ed25519_BYTES
  crypto_scalarmult_ed25519_SCALARBYTES
```

#### `crypto_pwhash`

[Password Hashing](https://sodium-friends.github.io/docs/docs/passwordhashing)

#### Methods
```
  crypto_pwhash
```

#### Constants
```
  crypto_pwhash_BYTES_MIN
  crypto_pwhash_BYTES_MAX
  crypto_pwhash_PASSWD_MIN
  crypto_pwhash_PASSWD_MAX
  crypto_pwhash_SALTBYTES
  crypto_pwhash_OPSLIMIT_MIN
  crypto_pwhash_OPSLIMIT_MAX
  crypto_pwhash_MEMLIMIT_MIN
  crypto_pwhash_MEMLIMIT_MAX
  crypto_pwhash_ALG_DEFAULT
  crypto_pwhash_ALG_ARGON2I13
  crypto_pwhash_ALG_ARGON2ID13
  crypto_pwhash_BYTES_MIN
  crypto_pwhash_BYTES_MAX
  crypto_pwhash_PASSWD_MIN
  crypto_pwhash_PASSWD_MAX
  crypto_pwhash_SALTBYTES
  crypto_pwhash_STRBYTES
  crypto_pwhash_OPSLIMIT_MIN
  crypto_pwhash_OPSLIMIT_MAX
  crypto_pwhash_MEMLIMIT_MIN
  crypto_pwhash_MEMLIMIT_MAX
  crypto_pwhash_OPSLIMIT_INTERACTIVE
  crypto_pwhash_MEMLIMIT_INTERACTIVE
  crypto_pwhash_OPSLIMIT_MODERATE
  crypto_pwhash_MEMLIMIT_MODERATE
  crypto_pwhash_OPSLIMIT_SENSITIVE
  crypto_pwhash_MEMLIMIT_SENSITIVE
```

#### `crypto_generichash`

[Blake2b hashing](https://sodium-friends.github.io/docs/docs/generichashing)

#### Methods
```
  crypto_generichash_init
  crypto_generichash_update
  crypto_generichash_final
  crypto_generichash_batch
```

#### Constants
```
  crypto_generichash_STATEBYTES
  crypto_generichash_KEYBYTES_MIN
  crypto_generichash_KEYBYTES_MAX
  crypto_generichash_BYTES
  crypto_generichash_BYTES_MIN
  crypto_generichash_BYTES_MAX
```

#### `crypto_kdf`

[Key derivation](https://sodium-friends.github.io/docs/docs/keyderivation)

#### Methods
```
  crypto_kdf_keygen
  crypto_kdf_derive_from_key
```

#### Constants
```
  crypto_kdf_KEYBYTES
  crypto_kdf_BYTES_MIN
  crypto_kdf_BYTES_MAX
  crypto_kdf_CONTEXTBYTES
```

#### `crypto_secretstream_xchacha20poly1305`

[Stream encryption](https://sodium-friends.github.io/docs/docs/streamencryption)

#### Methods
```
  crypto_secretstream_xchacha20poly1305_keygen
  crypto_secretstream_xchacha20poly1305_init_push
  crypto_secretstream_xchacha20poly1305_push
  crypto_secretstream_xchacha20poly1305_init_pull
  crypto_secretstream_xchacha20poly1305_pull
```

#### Constants
```
  crypto_secretstream_xchacha20poly1305_STATEBYTES
  crypto_secretstream_xchacha20poly1305_ABYTES
  crypto_secretstream_xchacha20poly1305_HEADERBYTES
  crypto_secretstream_xchacha20poly1305_KEYBYTES
  crypto_secretstream_xchacha20poly1305_TAGBYTES
  crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX

  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  crypto_secretstream_xchacha20poly1305_TAG_PUSH
  crypto_secretstream_xchacha20poly1305_TAG_REKEY
  crypto_secretstream_xchacha20poly1305_TAG_FINAL
```

#### `crypto_secretbox`

[Secret key box encryption](https://sodium-friends.github.io/docs/docs/secretkeyboxencryption)

#### Methods
```
  crypto_secretbox_easy
```

#### `randombytes_buf`

[Generating random data](https://sodium-friends.github.io/docs/docs/generatingrandomdata)

```
  randombytes_buf
```

### Utilities

Various [helpers](https://sodium-friends.github.io/docs/docs/helpers) for securely handling memory.

```
  sodium_memcmp  // constant time
  sodium_memzero
  sodium_free
  sodium_malloc
```

## License

MIT
