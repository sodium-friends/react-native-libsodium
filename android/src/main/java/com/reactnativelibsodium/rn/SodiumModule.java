package com.reactnativelibsodium.rn;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.Callback;

import java.nio.*;
import java.io.*;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import android.util.Log;
import org.json.JSONObject;
import org.json.JSONException;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.WritableNativeMap;
import com.reactnativelibsodium.jni.Sodium;
import com.reactnativelibsodium.helpers.*;

public class SodiumModule extends ReactContextBaseJavaModule {

  public SodiumModule(ReactApplicationContext reactContext) {
    super(reactContext);
    Sodium.loadLibrary();
  }

  @Override
  public String getName() {
      return "Sodium";
  }

  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put("crypto_generichash_STATEBYTES", Sodium.crypto_generichash_statebytes());
    constants.put("crypto_generichash_BYTES_MIN", Sodium.crypto_generichash_bytes_min());
    constants.put("crypto_generichash_BYTES_MAX", Sodium.crypto_generichash_bytes_max());
    constants.put("crypto_generichash_BYTES", Sodium.crypto_generichash_bytes());
    constants.put("crypto_generichash_KEYBYTES_MIN", Sodium.crypto_generichash_keybytes_min());
    constants.put("crypto_generichash_KEYBYTES_MAX", Sodium.crypto_generichash_keybytes_max());
    constants.put("crypto_generichash_KEYBYTES", Sodium.crypto_generichash_keybytes());
    constants.put("crypto_pwhash_ALG_ARGON2I13", Sodium.crypto_pwhash_alg_argon2i13());
    constants.put("crypto_pwhash_ALG_DEFAULT", Sodium.crypto_pwhash_alg_default());
    constants.put("crypto_pwhash_BYTES_MIN", Sodium.crypto_pwhash_bytes_min());
    constants.put("crypto_pwhash_BYTES_MAX", Sodium.crypto_pwhash_bytes_max());
    constants.put("crypto_pwhash_PASSWD_MIN", Sodium.crypto_pwhash_passwd_min());
    constants.put("crypto_pwhash_PASSWD_MAX", Sodium.crypto_pwhash_passwd_max());
    constants.put("crypto_pwhash_SALTBYTES", Sodium.crypto_pwhash_saltbytes());
    constants.put("crypto_pwhash_STRBYTES", Sodium.crypto_pwhash_strbytes());
    constants.put("crypto_pwhash_OPSLIMIT_MIN", Sodium.crypto_pwhash_opslimit_min());
    constants.put("crypto_pwhash_OPSLIMIT_MAX", Sodium.crypto_pwhash_opslimit_max());
    constants.put("crypto_pwhash_MEMLIMIT_MIN", Sodium.crypto_pwhash_memlimit_min());
    constants.put("crypto_pwhash_MEMLIMIT_MAX", Sodium.crypto_pwhash_memlimit_max());
    constants.put("crypto_pwhash_OPSLIMIT_INTERACTIVE", Sodium.crypto_pwhash_opslimit_interactive());
    constants.put("crypto_pwhash_MEMLIMIT_INTERACTIVE", Sodium.crypto_pwhash_memlimit_interactive());
    constants.put("crypto_pwhash_OPSLIMIT_MODERATE", Sodium.crypto_pwhash_opslimit_moderate());
    constants.put("crypto_pwhash_MEMLIMIT_MODERATE", Sodium.crypto_pwhash_memlimit_moderate());
    constants.put("crypto_pwhash_OPSLIMIT_SENSITIVE", Sodium.crypto_pwhash_opslimit_sensitive());
    constants.put("crypto_pwhash_MEMLIMIT_SENSITIVE", Sodium.crypto_pwhash_memlimit_sensitive());
    constants.put("crypto_scalarmult_BYTES", Sodium.crypto_scalarmult_bytes());
    constants.put("crypto_scalarmult_SCALARBYTES", Sodium.crypto_scalarmult_scalarbytes());
    constants.put("crypto_kdf_BYTES_MIN", Sodium.crypto_kdf_bytes_min());
    constants.put("crypto_kdf_BYTES_MAX", Sodium.crypto_kdf_bytes_max());
    constants.put("crypto_kdf_CONTEXTBYTES", Sodium.crypto_kdf_contextbytes());
    constants.put("crypto_kdf_KEYBYTES", Sodium.crypto_kdf_keybytes());
    constants.put("crypto_core_ed25519_BYTES", Sodium.crypto_core_ed25519_bytes());
    constants.put("crypto_core_ed25519_UNIFORMBYTES", Sodium.crypto_core_ed25519_uniformbytes());
    constants.put("crypto_core_ed25519_SCALARBYTES", Sodium.crypto_core_ed25519_scalarbytes());
    constants.put("crypto_core_ed25519_NONREDUCEDSCALARBYTES", Sodium.crypto_core_ed25519_nonreducedscalarbytes());
    constants.put("crypto_scalarmult_ed25519_BYTES", Sodium.crypto_scalarmult_ed25519_bytes());
    constants.put("crypto_scalarmult_ed25519_SCALARBYTES", Sodium.crypto_scalarmult_ed25519_scalarbytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_ABYTES", Sodium.crypto_aead_xchacha20poly1305_ietf_abytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_KEYBYTES", Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", Sodium.crypto_aead_xchacha20poly1305_ietf_npubbytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_NSECBYTES", Sodium.crypto_aead_xchacha20poly1305_ietf_nsecbytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX", Sodium.crypto_aead_xchacha20poly1305_ietf_messagebytes_max());
    constants.put("crypto_aead_chacha20poly1305_ietf_ABYTES", Sodium.crypto_aead_chacha20poly1305_ietf_abytes());
    constants.put("crypto_aead_chacha20poly1305_ietf_KEYBYTES", Sodium.crypto_aead_chacha20poly1305_ietf_keybytes());
    constants.put("crypto_aead_chacha20poly1305_ietf_NPUBBYTES", Sodium.crypto_aead_chacha20poly1305_ietf_npubbytes());
    constants.put("crypto_aead_chacha20poly1305_ietf_NSECBYTES", Sodium.crypto_aead_chacha20poly1305_ietf_nsecbytes());
    constants.put("crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX", Sodium.crypto_aead_chacha20poly1305_ietf_messagebytes_max());
    constants.put("crypto_secretstream_xchacha20poly1305_STATEBYTES", Sodium.crypto_secretstream_xchacha20poly1305_statebytes());
    constants.put("crypto_secretstream_xchacha20poly1305_ABYTES", Sodium.crypto_secretstream_xchacha20poly1305_abytes());
    constants.put("crypto_secretstream_xchacha20poly1305_HEADERBYTES", Sodium.crypto_secretstream_xchacha20poly1305_headerbytes());
    constants.put("crypto_secretstream_xchacha20poly1305_KEYBYTES", Sodium.crypto_secretstream_xchacha20poly1305_keybytes());
    constants.put("crypto_secretstream_xchacha20poly1305_TAGBYTES", 1);
    constants.put("crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX", Sodium.crypto_secretstream_xchacha20poly1305_messagebytes_max());
    constants.put("_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE", Sodium.crypto_secretstream_xchacha20poly1305_tag_message());
    constants.put("_crypto_secretstream_xchacha20poly1305_TAG_PUSH", Sodium.crypto_secretstream_xchacha20poly1305_tag_push());
    constants.put("_crypto_secretstream_xchacha20poly1305_TAG_REKEY", Sodium.crypto_secretstream_xchacha20poly1305_tag_rekey());
    constants.put("_crypto_secretstream_xchacha20poly1305_TAG_FINAL", Sodium.crypto_secretstream_xchacha20poly1305_tag_final());

    // These may be useful for future extensions

    // constants.put("crypto_onetimeauth_STATEBYTES", Sodium.crypto_onetimeauth_statebytes());
    // constants.put("crypto_hash_sha256_STATEBYTES", Sodium.crypto_hash_sha256_statebytes());
    // constants.put("crypto_hash_sha512_STATEBYTES", Sodium.crypto_hash_sha512_statebytes());
    // constants.put("crypto_stream_xor_STATEBYTES", Sodium.crypto_stream_xor_statebytes());
    // constants.put("crypto_stream_chacha20_xor_STATEBYTES", Sodium.crypto_stream_chacha20_xor_statebytes());
    // constants.put("randombytes_SEEDBYTES", Sodium.randombytes_seedbytes());
    // constants.put("crypto_sign_SEEDBYTES", Sodium.crypto_sign_seedbytes());
    // constants.put("crypto_sign_PUBLICKEYBYTES", Sodium.crypto_sign_publickeybytes());
    // constants.put("crypto_sign_SECRETKEYBYTES", Sodium.crypto_sign_secretkeybytes());
    // constants.put("crypto_sign_BYTES", Sodium.crypto_sign_bytes());
    // constants.put("crypto_hash_BYTES", Sodium.crypto_hash_bytes());
    // constants.put("crypto_box_SEEDBYTES", Sodium.crypto_box_seedbytes());
    // constants.put("crypto_box_PUBLICKEYBYTES", Sodium.crypto_box_publickeybytes());
    // constants.put("crypto_box_SECRETKEYBYTES", Sodium.crypto_box_secretkeybytes());
    // constants.put("crypto_box_NONCEBYTES", Sodium.crypto_box_noncebytes());
    // constants.put("crypto_box_MACBYTES", Sodium.crypto_box_macbytes());
    // constants.put("crypto_secretbox_KEYBYTES", Sodium.crypto_secretbox_keybytes());
    // constants.put("crypto_secretbox_NONCEBYTES", Sodium.crypto_secretbox_noncebytes());
    // constants.put("crypto_secretbox_MACBYTES", Sodium.crypto_secretbox_macbytes());
    // constants.put("crypto_box_SEALBYTES", Sodium.crypto_box_sealbytes());
    // constants.put("crypto_stream_KEYBYTES", Sodium.crypto_stream_keybytes());
    // constants.put("crypto_stream_NONCEBYTES", Sodium.crypto_stream_noncebytes());
    // constants.put("crypto_stream_chacha20_KEYBYTES", Sodium.crypto_stream_chacha20_keybytes());
    // constants.put("crypto_stream_chacha20_NONCEBYTES", Sodium.crypto_stream_chacha20_noncebytes());
    // constants.put("crypto_auth_BYTES", Sodium.crypto_auth_bytes());
    // constants.put("crypto_auth_KEYBYTES", Sodium.crypto_auth_keybytes());
    // constants.put("crypto_onetimeauth_BYTES", Sodium.crypto_onetimeauth_bytes());
    // constants.put("crypto_onetimeauth_KEYBYTES", Sodium.crypto_onetimeauth_keybytes());
    // constants.put("crypto_pwhash_ALG_ARGON2ID13", Sodium.crypto_pwhash_alg_argon2id13());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_BYTES_MIN", Sodium.crypto_pwhash_scryptsalsa208sha256_bytes_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_BYTES_MAX", Sodium.crypto_pwhash_scryptsalsa208sha256_bytes_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN", Sodium.crypto_pwhash_scryptsalsa208sha256_passwd_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX", Sodium.crypto_pwhash_scryptsalsa208sha256_passwd_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_SALTBYTES", Sodium.crypto_pwhash_scryptsalsa208sha256_saltbytes());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_STRBYTES", Sodium.crypto_pwhash_scryptsalsa208sha256_strbytes());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN", Sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX", Sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN", Sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX", Sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE", Sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE", Sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE", Sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE", Sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive());
    // constants.put("crypto_shorthash_BYTES", Sodium.crypto_shorthash_bytes());
    // constants.put("crypto_shorthash_KEYBYTES", Sodium.crypto_shorthash_keybytes());
    // constants.put("crypto_hash_sha256_BYTES", Sodium.crypto_hash_sha256_bytes());
    // constants.put("crypto_hash_sha512_BYTES", Sodium.crypto_hash_sha512_bytes());
    // constants.put("crypto_kx_PUBLICKEYBYTES", Sodium.crypto_kx_publickeybytes());
    // constants.put("crypto_kx_SECRETKEYBYTES", Sodium.crypto_kx_secretkeybytes());
    // constants.put("crypto_kx_SEEDBYTES", Sodium.crypto_kx_seedbytes());
    // constants.put("crypto_kx_SESSIONKEYBYTES", Sodium.crypto_kx_sessionkeybytes());

    return constants;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_keygen (ReadableArray k) throws Exception {
    byte[] key = ArgumentsEx.toByteArray(k);

    try {
      ArgumentsEx.check(key, Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key);

    return ArrayUtil.toWritableArray(key);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray randombytes_buf(ReadableArray in) throws Exception {
    byte[] buf = ArgumentsEx.toByteArray(in);

    Sodium.randombytes_buf(buf, buf.length);

    return ArrayUtil.toWritableArray(buf);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_encrypt (
      ReadableArray c,
      ReadableArray m,
      ReadableArray ad,
      ReadableArray nsec,
      ReadableArray npub,
      ReadableArray k
  ) throws Exception {
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] clen_p = new int[1];

    try {
      ArgumentsEx.check(_npub, Sodium.crypto_aead_xchacha20poly1305_ietf_npubbytes(),"ERR_BAD_NPUB");
      ArgumentsEx.check(_k, Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes(), "ERR_BAD_KEY");
      ArgumentsEx.check(_c, _m.length + Sodium.crypto_aead_xchacha20poly1305_ietf_abytes(), "ERR_BAD_CIPHERTEXT");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      _c, clen_p,
      _m, m.size(),
      _ad, ad.size(),
      _nsec, _npub, _k);
    
    return ArrayUtil.toWritableArray( Arrays.copyOfRange(_c, 0, clen_p[0] ) );
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_decrypt (
      ReadableArray m,
      ReadableArray nsec,
      ReadableArray c,
      ReadableArray ad,
      ReadableArray npub,
      ReadableArray k
  ) throws Exception {
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] mlen_p = new int[1];

    try {
      ArgumentsEx.check(_npub, Sodium.crypto_aead_xchacha20poly1305_ietf_npubbytes(), "ERR_BAD_NPUB");
      ArgumentsEx.check(_k, Sodium.crypto_aead_xchacha20poly1305_ietf_keybytes(), "ERR_BAD_KEY");
      ArgumentsEx.check(_m, _c.length - Sodium.crypto_aead_xchacha20poly1305_ietf_abytes(), "ERR_BAD_MSG");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      _m, mlen_p,
      _nsec,
      _c,  c.size(),
      _ad, ad.size(),
      _npub, _k);
    
    return ArrayUtil.toWritableArray( Arrays.copyOfRange(_m, 0, mlen_p[0] ) );
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_chacha20poly1305_ietf_encrypt (
      ReadableArray c,
      ReadableArray m,
      ReadableArray ad,
      ReadableArray nsec,
      ReadableArray npub,
      ReadableArray k
  ) throws Exception {
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] clen_p = new int[1];

    try {
      ArgumentsEx.check(_npub, Sodium.crypto_aead_chacha20poly1305_ietf_npubbytes(),"ERR_BAD_NPUB");
      ArgumentsEx.check(_k, Sodium.crypto_aead_chacha20poly1305_ietf_keybytes(), "ERR_BAD_KEY");
      ArgumentsEx.check(_c, _m.length + Sodium.crypto_aead_chacha20poly1305_ietf_abytes(), "ERR_BAD_CIPHERTEXT");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      _c, clen_p,
      _m, m.size(),
      _ad, ad.size(),
      _nsec, _npub, _k);

    return ArrayUtil.toWritableArray( Arrays.copyOfRange(_c, 0, clen_p[0] ) );
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_chacha20poly1305_ietf_decrypt (
      ReadableArray m,
      ReadableArray nsec,
      ReadableArray c,
      ReadableArray ad,
      ReadableArray npub,
      ReadableArray k
  ) throws Exception {
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] mlen_p = new int[1];

    try {
      ArgumentsEx.check(_npub, Sodium.crypto_aead_chacha20poly1305_ietf_npubbytes(), "ERR_BAD_NPUB");
      ArgumentsEx.check(_k, Sodium.crypto_aead_chacha20poly1305_ietf_keybytes(), "ERR_BAD_KEY");
      ArgumentsEx.check(_m, _c.length - Sodium.crypto_aead_chacha20poly1305_ietf_abytes(), "ERR_BAD_MSG");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      _m, mlen_p,
      _nsec,
      _c,  c.size(),
      _ad, ad.size(),
      _npub, _k);

    return ArrayUtil.toWritableArray( Arrays.copyOfRange(_m, 0, mlen_p[0] ) );
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_keygen (ReadableArray k) throws Exception {
    byte[] key = ArgumentsEx.toByteArray(k);

    try {
      ArgumentsEx.check(key, Sodium.crypto_secretstream_xchacha20poly1305_keybytes(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_secretstream_xchacha20poly1305_keygen(key);

    return ArrayUtil.toWritableArray(key);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_kx_keypair (ReadableArray pk, ReadableArray sk) throws Exception {
    byte[] _pk = ArgumentsEx.toByteArray(pk);
    byte[] _sk = ArgumentsEx.toByteArray(sk);

    try {
      ArgumentsEx.check(_pk, Sodium.crypto_kx_publickeybytes(), "ERR_BAD_KEY");
      ArgumentsEx.check(_sk, Sodium.crypto_kx_secretkeybytes(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_kx_keypair(_pk, _sk);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

    try {
      outputStream.write( _pk );
      outputStream.write( _sk );
    } catch (IOException e) {
      throw e;
    }

    byte ret[] = outputStream.toByteArray( );

    return ArrayUtil.toWritableArray(ret);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_init_push (
      ReadableArray state,
      ReadableArray header,
      ReadableArray k
  ) throws Exception {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _header = ArgumentsEx.toByteArray(header);
    byte[] _k = ArgumentsEx.toByteArray(k);

    try {
      ArgumentsEx.check(_state, Sodium.crypto_secretstream_xchacha20poly1305_statebytes(), "ERR_BAD_STATE");
      ArgumentsEx.check(_header, Sodium.crypto_secretstream_xchacha20poly1305_headerbytes(), "ERR_BAD_HEADER");
      ArgumentsEx.check(_k, Sodium.crypto_secretstream_xchacha20poly1305_keybytes(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_secretstream_xchacha20poly1305_init_push(_state, _header, _k);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

    try {
      outputStream.write( _state );
      outputStream.write( _header ); // put dynamic length entry last
    } catch (IOException e) {
      throw e;
    }

    byte ret[] = outputStream.toByteArray( );

    return ArrayUtil.toWritableArray(ret);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_push (
      ReadableArray state,
      ReadableArray c,
      ReadableArray m,
      ReadableArray ad,
      ReadableArray tag
  ) throws Exception {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _tag = ArgumentsEx.toByteArray(tag);
    int[] clen_p = new int[1];

    try {
      ArgumentsEx.check(_state, Sodium.crypto_secretstream_xchacha20poly1305_statebytes(), "ERR_BAD_STATE");
      ArgumentsEx.check(_m, _c.length - Sodium.crypto_secretstream_xchacha20poly1305_abytes(), "ERR_BAD_CIPHERTEXT_LENGTH");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_secretstream_xchacha20poly1305_push(_state, _c, clen_p, _m, _m.length, _ad, _ad.length, _tag);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

    try {
      outputStream.write( _state );
      outputStream.write( Arrays.copyOfRange(_c, 0, clen_p[0] ) ); // put dynamic length entry last
    } catch (IOException e) {
      throw e;
    }

    byte ret[] = outputStream.toByteArray( );

    return ArrayUtil.toWritableArray(ret);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_init_pull (
      ReadableArray state,
      ReadableArray header,
      ReadableArray k
  ) throws Exception {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _header = ArgumentsEx.toByteArray(header);
    byte[] _k = ArgumentsEx.toByteArray(k);

    try {
      ArgumentsEx.check(_state, Sodium.crypto_secretstream_xchacha20poly1305_statebytes(), "ERR_BAD_STATE");
      ArgumentsEx.check(_header, Sodium.crypto_secretstream_xchacha20poly1305_headerbytes(), "ERR_BAD_HEADER");
      ArgumentsEx.check(_k, Sodium.crypto_secretstream_xchacha20poly1305_keybytes(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_secretstream_xchacha20poly1305_init_pull(_state, _header, _k);
    
    return ArrayUtil.toWritableArray(_state);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_pull (
      ReadableArray state,
      ReadableArray m,
      ReadableArray tag,
      ReadableArray c,
      ReadableArray ad
  ) throws Exception {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _tag = ArgumentsEx.toByteArray(tag);
    int[] mlen_p = new int[1];

    try {
      ArgumentsEx.check(_state, Sodium.crypto_secretstream_xchacha20poly1305_statebytes(), "ERR_BAD_STATE");
      ArgumentsEx.check(_m, _c.length - Sodium.crypto_secretstream_xchacha20poly1305_abytes(), "ERR_BAD_MESSAGE_LENGTH");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_secretstream_xchacha20poly1305_pull(_state, _m, mlen_p, _tag, _c, _c.length, _ad, _ad.length);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

    try {
      outputStream.write( _state );
      outputStream.write( _tag );
      outputStream.write( Arrays.copyOfRange(_m, 0, mlen_p[0] ) ); // put dynamic length entry last
    } catch (IOException e) {
      throw e;
    }

    byte ret[] = outputStream.toByteArray( );

    return ArrayUtil.toWritableArray(ret);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_scalar_random (ReadableArray r) throws Exception {
    byte[] _r = ArgumentsEx.toByteArray(r);

    try {
      ArgumentsEx.check(_r, Sodium.crypto_core_ed25519_scalarbytes(), "ERR_BAD_SCALAR");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_core_ed25519_scalar_random(_r);

    return ArrayUtil.toWritableArray(_r);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_add (
      ReadableArray r,
      ReadableArray p,
      ReadableArray q
  ) throws Exception {
    byte[] _r = ArgumentsEx.toByteArray(r);
    byte[] _p = ArgumentsEx.toByteArray(p);
    byte[] _q = ArgumentsEx.toByteArray(q);

    try {
      ArgumentsEx.check(_r, Sodium.crypto_core_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_p, Sodium.crypto_core_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_q, Sodium.crypto_core_ed25519_bytes(), "ERR_BAD_EC_POINT");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_core_ed25519_add(_r, _p, _q);

    return ArrayUtil.toWritableArray(_r);
  }
  
  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_sub (
      ReadableArray r,
      ReadableArray p,
      ReadableArray q)
  throws Exception {
    byte[] _r = ArgumentsEx.toByteArray(r);
    byte[] _p = ArgumentsEx.toByteArray(p);
    byte[] _q = ArgumentsEx.toByteArray(q);

    try {
      ArgumentsEx.check(_r, Sodium.crypto_core_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_p, Sodium.crypto_core_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_q, Sodium.crypto_core_ed25519_bytes(), "ERR_BAD_EC_POINT");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_core_ed25519_sub(_r, _p, _q);

    return ArrayUtil.toWritableArray(_r);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_from_uniform (
      ReadableArray p,
      ReadableArray r
  ) throws Exception {
    byte[] _p = ArgumentsEx.toByteArray(p);
    byte[] _r = ArgumentsEx.toByteArray(r);

    try {
      ArgumentsEx.check(_p, Sodium.crypto_core_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_r, Sodium.crypto_core_ed25519_uniformbytes(), "ERR_BAD_SEED");
    } catch (Exception e) {
      throw e;
    }
  
    Sodium.crypto_core_ed25519_from_uniform(_p, _r);

    return ArrayUtil.toWritableArray(_p);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_pwhash (
      ReadableArray out,
      ReadableArray passwd,
      ReadableArray salt,
      int opslimit,
      int memlimit,
      int alg
  ) throws Exception {
    byte[] _out = ArgumentsEx.toByteArray(out);
    byte[] _passwd = ArgumentsEx.toByteArray(passwd);
    byte[] _salt = ArgumentsEx.toByteArray(salt);

    try {
      ArgumentsEx.check(_out, Sodium.crypto_pwhash_bytes_min(), Sodium.crypto_pwhash_bytes_max(), "ERR_BAD_OUTPUT");
      ArgumentsEx.check(_passwd, Sodium.crypto_pwhash_passwd_min(), Sodium.crypto_pwhash_passwd_max(), "ERR_BAD_PWD");
      ArgumentsEx.check(_salt, Sodium.crypto_pwhash_saltbytes(), "ERR_BAD_SALT");
      ArgumentsEx.check(opslimit, Sodium.crypto_pwhash_opslimit_min(), Sodium.crypto_pwhash_opslimit_max(), "ERR_BAD_OPS");
      ArgumentsEx.check(memlimit, Sodium.crypto_pwhash_memlimit_min(), Sodium.crypto_pwhash_memlimit_max(), "ERR_BAD_MEM");
    } catch (Exception e) {
      throw e;
    }

    int ret = Sodium.crypto_pwhash(_out, _out.length, _passwd, _passwd.length, _salt, opslimit, memlimit, alg);

    return ArrayUtil.toWritableArray(_out);
  }

  @ReactMethod
  public void crypto_pwhash_async (
      ReadableArray out,
      ReadableArray passwd,
      ReadableArray salt,
      int opslimit,
      int memlimit,
      int alg,
      Promise promise
  ) {
    byte[] _out = ArgumentsEx.toByteArray(out);
    byte[] _passwd = ArgumentsEx.toByteArray(passwd);
    byte[] _salt = ArgumentsEx.toByteArray(salt);

    try {
      ArgumentsEx.check(_out, Sodium.crypto_pwhash_bytes_min(), Sodium.crypto_pwhash_bytes_max(), "ERR_BAD_OUTPUT");
      ArgumentsEx.check(_passwd, Sodium.crypto_pwhash_passwd_min(), Sodium.crypto_pwhash_passwd_max(), "ERR_BAD_PWD");
      ArgumentsEx.check(_salt, Sodium.crypto_pwhash_saltbytes(), "ERR_BAD_SALT");
      ArgumentsEx.check(opslimit, Sodium.crypto_pwhash_opslimit_min(), Sodium.crypto_pwhash_opslimit_max(), "ERR_BAD_OPS");
      ArgumentsEx.check(memlimit, Sodium.crypto_pwhash_memlimit_min(), Sodium.crypto_pwhash_memlimit_max(), "ERR_BAD_MEM");
    } catch (Exception e) {
      promise.reject("crypto_pwhash bad arguments:", e);
    }

    int ret = Sodium.crypto_pwhash(_out, _out.length, _passwd, _passwd.length, _salt, opslimit, memlimit, alg);

    if (ret != 0) {
      Exception e = new Exception("crypto_pwhash execution failed");
      promise.reject("crypto_pwhash execution failed", e);
    }

    WritableArray buf = ArrayUtil.toWritableArray(_out);
    promise.resolve(buf);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519 (
      ReadableArray q,
      ReadableArray n,
      ReadableArray p
  ) throws Exception {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);
    byte[] _p = ArgumentsEx.toByteArray(p);

    try {
      ArgumentsEx.check(_q, Sodium.crypto_scalarmult_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_n, Sodium.crypto_scalarmult_ed25519_scalarbytes(), "ERR_BAD_SCALAR");
      ArgumentsEx.check(_p, Sodium.crypto_scalarmult_ed25519_bytes(), "ERR_BAD_EC_POINT");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_scalarmult_ed25519(_q, _n, _p);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519_noclamp (
      ReadableArray q,
      ReadableArray n,
      ReadableArray p
  ) throws Exception {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);
    byte[] _p = ArgumentsEx.toByteArray(p);

    try {
      ArgumentsEx.check(_q, Sodium.crypto_scalarmult_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_n, Sodium.crypto_scalarmult_ed25519_scalarbytes(), "ERR_BAD_SCALAR");
      ArgumentsEx.check(_p, Sodium.crypto_scalarmult_ed25519_bytes(), "ERR_BAD_EC_POINT");
    } catch (Exception e) {
      throw e;
    }
  
    Sodium.crypto_scalarmult_ed25519_noclamp(_q, _n, _p);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519_base (
      ReadableArray q,
      ReadableArray n
  ) throws Exception {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);

    try {
      ArgumentsEx.check(_q, Sodium.crypto_scalarmult_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_n, Sodium.crypto_scalarmult_ed25519_scalarbytes(), "ERR_BAD_SCALAR");
    } catch (Exception e) {
      throw e;
    }
  
    Sodium.crypto_scalarmult_ed25519_base(_q, _n);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519_base_noclamp (
      ReadableArray q,
      ReadableArray n
  ) throws Exception {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);

    try {
      ArgumentsEx.check(_q, Sodium.crypto_scalarmult_ed25519_bytes(), "ERR_BAD_EC_POINT");
      ArgumentsEx.check(_n, Sodium.crypto_scalarmult_ed25519_scalarbytes(), "ERR_BAD_SCALAR");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_scalarmult_ed25519_base_noclamp(_q, _n);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_generichash_init (
      ReadableArray state,
      ReadableArray key,
      double outlen
  ) throws Exception {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _key = ArgumentsEx.toByteArray(key);

    try {
      ArgumentsEx.check(_state, Sodium.crypto_generichash_statebytes(), "ERR_BAD_STATE");
      ArgumentsEx.check(_key, Sodium.crypto_generichash_keybytes_min(),
                              Sodium.crypto_generichash_keybytes_max(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_generichash_init(_state, _key, _key.length, (int) outlen);

    return ArrayUtil.toWritableArray(_state);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_generichash_update (
      ReadableArray state,
      ReadableArray in
  ) throws Exception {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _in = ArgumentsEx.toByteArray(in);

    try {
      ArgumentsEx.check(_state, Sodium.crypto_generichash_statebytes(), "ERR_BAD_STATE");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_generichash_update(_state, _in, _in.length);

    return ArrayUtil.toWritableArray(_state);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_generichash_final (
      ReadableArray state,
      ReadableArray out
  ) throws Exception {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _out = ArgumentsEx.toByteArray(out);

    try {
      ArgumentsEx.check(_state, Sodium.crypto_generichash_statebytes(), "ERR_BAD_STATE");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_generichash_final(_state, _out, _out.length);

    return ArrayUtil.toWritableArray(_out);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_kdf_keygen (ReadableArray key) throws Exception {
    byte[] _key = ArgumentsEx.toByteArray(key);

    try {
      ArgumentsEx.check(_key, Sodium.crypto_kdf_keybytes(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_kdf_keygen(_key);

    return ArrayUtil.toWritableArray(_key);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_kdf_derive_from_key (
      ReadableArray subkey,
      int subkey_id,
      ReadableArray ctx,
      ReadableArray key
  ) throws Exception {
    byte[] _subkey = ArgumentsEx.toByteArray(subkey);
    byte[] _ctx = ArgumentsEx.toByteArray(ctx);
    byte[] _key = ArgumentsEx.toByteArray(key);

    try {
      ArgumentsEx.check(_subkey, Sodium.crypto_kdf_bytes_min(), Sodium.crypto_kdf_bytes_max(), "ERR_BAD_SUBKEY");
      ArgumentsEx.check(_ctx, Sodium.crypto_kdf_contextbytes(), "ERR_BAD_CONTEXT");
      ArgumentsEx.check(_key, Sodium.crypto_kdf_keybytes(), "ERR_BAD_KEY");
    } catch (Exception e) {
      throw e;
    }

    Sodium.crypto_kdf_derive_from_key(_subkey, _subkey.length, subkey_id, _ctx, _key);

    return ArrayUtil.toWritableArray(_subkey);
  }
}
