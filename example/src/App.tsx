import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import Libsodium from 'react-native-libsodium';
console.log('hello', Libsodium)


export default function App() {
  const [result, setResult] = React.useState<number | undefined>();

  const key = new Uint8Array(32)
  Libsodium.crypto_kdf_keygen(key)
  console.log(key)
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
