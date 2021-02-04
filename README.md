# react-native-libsodium

react native lisodium

## Installation

```sh
npm install react-native-libsodium
```

## Usage

```js
import sodium from "react-native-libsodium";

// ...

const key = new Uint8Array(sodium.crypto_kdf_KEYBYTES)
const result = await sodium.crypto_kdf_keygen(key);
```

## License

MIT
