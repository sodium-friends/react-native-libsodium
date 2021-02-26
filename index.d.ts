export const crypto_pwhash_ALG_ARGON2I13: number;
export const crypto_pwhash_ALG_ARGON2ID13: number;
export const crypto_pwhash_ALG_DEFAULT: number;
export const crypto_pwhash_BYTES_MAX: number;
export const crypto_pwhash_BYTES_MIN: number;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE: number;
export const crypto_pwhash_MEMLIMIT_MAX: number;
export const crypto_pwhash_MEMLIMIT_MIN: number;
export const crypto_pwhash_MEMLIMIT_MODERATE: number;
export const crypto_pwhash_MEMLIMIT_SENSITIVE: number;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
export const crypto_pwhash_OPSLIMIT_MAX: number;
export const crypto_pwhash_OPSLIMIT_MIN: number;
export const crypto_pwhash_OPSLIMIT_MODERATE: number;
export const crypto_pwhash_OPSLIMIT_SENSITIVE: number;
export const crypto_pwhash_PASSWD_MAX: number;
export const crypto_pwhash_PASSWD_MIN: number;
export const crypto_pwhash_SALTBYTES: number;
export const crypto_pwhash_STR_VERIFY: number;
export const crypto_pwhash_STRBYTES: number;
export const crypto_pwhash_STRPREFIX: string;
export const crypto_aead_xchacha20poly1305_IETF_ABYTES: number;
export const crypto_aead_xchacha20poly1305_IETF_KEYBYTES: number;
export const crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: number;
export const crypto_aead_xchacha20poly1305_IETF_NSECBYTES: number;
export const randombytes_SEEDBYTES: number;
export const base64_variant_ORIGINAL: number;
export const base64_variant_VARIANT_ORIGINAL_NO_PADDING: number;
export const base64_variant_VARIANT_URLSAFE: number;
export const base64_variant_VARIANT_URLSAFE_NO_PADDING: number;

export function crypto_auth(message: string, key: string): Promise<string>;

export function crypto_pwhash(
  keyLength: number,
  password: string,
  salt: string,
  opsLimit: number,
  memLimit: number,
  algorithm: number
): Promise<string>;

export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string,
  public_nonce: string,
  key: string,
  additional_data: string | null
): Promise<string>;

export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  cipherText: string,
  public_nonce: string,
  key: string,
  additional_data: string | null
): Promise<string>;

export function crypto_aead_xchacha20poly1305_ietf_keygen(): Promise<string>;

export function randombytes_buf(length: number): Promise<string>;

export function randombytes_random(): Promise<number>;

export function sodium_version_string(): Promise<string>;

export function to_base64(message: string, variant: number): Promise<string>;

export function from_base64(cipher: string, variant: number): Promise<string>;

export function to_hex(message: string): Promise<string>;

export function from_hex(cipher: string): Promise<string>;
