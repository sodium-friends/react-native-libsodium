import { NativeModules } from 'react-native';

type LibsodiumType = {
  multiply(a: number, b: number): Promise<number>;
};

const { Libsodium } = NativeModules;

export default Libsodium as LibsodiumType;
