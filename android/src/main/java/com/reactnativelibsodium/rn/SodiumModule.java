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
import com.reactnativelibsodium.jni.NaCl;
import com.reactnativelibsodium.helpers.*;

public class SodiumModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;

  private Sodium sodium = NaCl.sodium();

  public SodiumModule(ReactApplicationContext reactContext) {
      super(reactContext);
      this.reactContext = reactContext;
  }

  @Override
  public String getName() {
      return "Sodium";
  }
  
  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put("crypto_generichash_STATEBYTES", this.sodium.crypto_generichash_statebytes());
    // constants.put("crypto_onetimeauth_STATEBYTES", this.sodium.crypto_onetimeauth_statebytes());
    // constants.put("crypto_hash_sha256_STATEBYTES", this.sodium.crypto_hash_sha256_statebytes());
    // constants.put("crypto_hash_sha512_STATEBYTES", this.sodium.crypto_hash_sha512_statebytes());
    // constants.put("crypto_secretstream_xchacha20poly1305_STATEBYTES", this.sodium.crypto_secretstream_xchacha20poly1305_statebytes());
    // constants.put("crypto_stream_xor_STATEBYTES", this.sodium.crypto_stream_xor_statebytes());
    // constants.put("crypto_stream_chacha20_xor_STATEBYTES", this.sodium.crypto_stream_chacha20_xor_statebytes());
    // constants.put("randombytes_SEEDBYTES", this.sodium.randombytes_seedbytes());
    // constants.put("crypto_sign_SEEDBYTES", this.sodium.crypto_sign_seedbytes());
    // constants.put("crypto_sign_PUBLICKEYBYTES", this.sodium.crypto_sign_publickeybytes());
    // constants.put("crypto_sign_SECRETKEYBYTES", this.sodium.crypto_sign_secretkeybytes());
    // constants.put("crypto_sign_BYTES", this.sodium.crypto_sign_bytes());
    constants.put("crypto_generichash_BYTES_MIN", this.sodium.crypto_generichash_bytes_min());
    constants.put("crypto_generichash_BYTES_MAX", this.sodium.crypto_generichash_bytes_max());
    constants.put("crypto_generichash_BYTES", this.sodium.crypto_generichash_bytes());
    constants.put("crypto_generichash_KEYBYTES_MIN", this.sodium.crypto_generichash_keybytes_min());
    constants.put("crypto_generichash_KEYBYTES_MAX", this.sodium.crypto_generichash_keybytes_max());
    constants.put("crypto_generichash_KEYBYTES", this.sodium.crypto_generichash_keybytes());
    // constants.put("crypto_hash_BYTES", this.sodium.crypto_hash_bytes());
    // constants.put("crypto_box_SEEDBYTES", this.sodium.crypto_box_seedbytes());
    // constants.put("crypto_box_PUBLICKEYBYTES", this.sodium.crypto_box_publickeybytes());
    // constants.put("crypto_box_SECRETKEYBYTES", this.sodium.crypto_box_secretkeybytes());
    // constants.put("crypto_box_NONCEBYTES", this.sodium.crypto_box_noncebytes());
    // constants.put("crypto_box_MACBYTES", this.sodium.crypto_box_macbytes());
    // constants.put("crypto_secretbox_KEYBYTES", this.sodium.crypto_secretbox_keybytes());
    // constants.put("crypto_secretbox_NONCEBYTES", this.sodium.crypto_secretbox_noncebytes());
    // constants.put("crypto_secretbox_MACBYTES", this.sodium.crypto_secretbox_macbytes());
    // constants.put("crypto_box_SEALBYTES", this.sodium.crypto_box_sealbytes());
    // constants.put("crypto_stream_KEYBYTES", this.sodium.crypto_stream_keybytes());
    // constants.put("crypto_stream_NONCEBYTES", this.sodium.crypto_stream_noncebytes());
    // constants.put("crypto_stream_chacha20_KEYBYTES", this.sodium.crypto_stream_chacha20_keybytes());
    // constants.put("crypto_stream_chacha20_NONCEBYTES", this.sodium.crypto_stream_chacha20_noncebytes());
    // constants.put("crypto_auth_BYTES", this.sodium.crypto_auth_bytes());
    // constants.put("crypto_auth_KEYBYTES", this.sodium.crypto_auth_keybytes());
    // constants.put("crypto_onetimeauth_BYTES", this.sodium.crypto_onetimeauth_bytes());
    // constants.put("crypto_onetimeauth_KEYBYTES", this.sodium.crypto_onetimeauth_keybytes());
    constants.put("crypto_pwhash_ALG_ARGON2I13", this.sodium.crypto_pwhash_alg_argon2i13());
    // constants.put("crypto_pwhash_ALG_ARGON2ID13", this.sodium.crypto_pwhash_alg_argon2id13());
    constants.put("crypto_pwhash_ALG_DEFAULT", this.sodium.crypto_pwhash_alg_default());
    constants.put("crypto_pwhash_BYTES_MIN", this.sodium.crypto_pwhash_bytes_min());
    constants.put("crypto_pwhash_BYTES_MAX", this.sodium.crypto_pwhash_bytes_max());
    constants.put("crypto_pwhash_PASSWD_MIN", this.sodium.crypto_pwhash_passwd_min());
    constants.put("crypto_pwhash_PASSWD_MAX", this.sodium.crypto_pwhash_passwd_max());
    constants.put("crypto_pwhash_SALTBYTES", this.sodium.crypto_pwhash_saltbytes());
    constants.put("crypto_pwhash_STRBYTES", this.sodium.crypto_pwhash_strbytes());
    constants.put("crypto_pwhash_OPSLIMIT_MIN", this.sodium.crypto_pwhash_opslimit_min());
    constants.put("crypto_pwhash_OPSLIMIT_MAX", this.sodium.crypto_pwhash_opslimit_max());
    constants.put("crypto_pwhash_MEMLIMIT_MIN", this.sodium.crypto_pwhash_memlimit_min());
    constants.put("crypto_pwhash_MEMLIMIT_MAX", this.sodium.crypto_pwhash_memlimit_max());
    constants.put("crypto_pwhash_OPSLIMIT_INTERACTIVE", this.sodium.crypto_pwhash_opslimit_interactive());
    constants.put("crypto_pwhash_MEMLIMIT_INTERACTIVE", this.sodium.crypto_pwhash_memlimit_interactive());
    constants.put("crypto_pwhash_OPSLIMIT_MODERATE", this.sodium.crypto_pwhash_opslimit_moderate());
    constants.put("crypto_pwhash_MEMLIMIT_MODERATE", this.sodium.crypto_pwhash_memlimit_moderate());
    constants.put("crypto_pwhash_OPSLIMIT_SENSITIVE", this.sodium.crypto_pwhash_opslimit_sensitive());
    constants.put("crypto_pwhash_MEMLIMIT_SENSITIVE", this.sodium.crypto_pwhash_memlimit_sensitive());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_BYTES_MIN", this.sodium.crypto_pwhash_scryptsalsa208sha256_bytes_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_BYTES_MAX", this.sodium.crypto_pwhash_scryptsalsa208sha256_bytes_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN", this.sodium.crypto_pwhash_scryptsalsa208sha256_passwd_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX", this.sodium.crypto_pwhash_scryptsalsa208sha256_passwd_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_SALTBYTES", this.sodium.crypto_pwhash_scryptsalsa208sha256_saltbytes());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_STRBYTES", this.sodium.crypto_pwhash_scryptsalsa208sha256_strbytes());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN", this.sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX", this.sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN", this.sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_min());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX", this.sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_max());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE", this.sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE", this.sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE", this.sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive());
    // constants.put("crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE", this.sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive());
    constants.put("crypto_scalarmult_BYTES", this.sodium.crypto_scalarmult_bytes());
    constants.put("crypto_scalarmult_SCALARBYTES", this.sodium.crypto_scalarmult_scalarbytes());
    // constants.put("crypto_shorthash_BYTES", this.sodium.crypto_shorthash_bytes());
    // constants.put("crypto_shorthash_KEYBYTES", this.sodium.crypto_shorthash_keybytes());
    constants.put("crypto_kdf_BYTES_MIN", this.sodium.crypto_kdf_bytes_min());
    constants.put("crypto_kdf_BYTES_MAX", this.sodium.crypto_kdf_bytes_max());
    constants.put("crypto_kdf_CONTEXTBYTES", this.sodium.crypto_kdf_contextbytes());
    constants.put("crypto_kdf_KEYBYTES", this.sodium.crypto_kdf_keybytes());
    // constants.put("crypto_hash_sha256_BYTES", this.sodium.crypto_hash_sha256_bytes());
    // constants.put("crypto_hash_sha512_BYTES", this.sodium.crypto_hash_sha512_bytes());
    constants.put("crypto_core_ed25519_BYTES", this.sodium.crypto_core_ed25519_bytes());
    constants.put("crypto_core_ed25519_UNIFORMBYTES", this.sodium.crypto_core_ed25519_uniformbytes());
    constants.put("crypto_core_ed25519_SCALARBYTES", this.sodium.crypto_core_ed25519_scalarbytes());
    constants.put("crypto_core_ed25519_NONREDUCEDSCALARBYTES", this.sodium.crypto_core_ed25519_nonreducedscalarbytes());
    constants.put("crypto_scalarmult_ed25519_BYTES", this.sodium.crypto_scalarmult_ed25519_bytes());
    constants.put("crypto_scalarmult_ed25519_SCALARBYTES", this.sodium.crypto_scalarmult_ed25519_scalarbytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_ABYTES", this.sodium.crypto_aead_xchacha20poly1305_ietf_abytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_KEYBYTES", this.sodium.crypto_aead_xchacha20poly1305_ietf_keybytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", this.sodium.crypto_aead_xchacha20poly1305_ietf_npubbytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_NSECBYTES", this.sodium.crypto_aead_xchacha20poly1305_ietf_nsecbytes());
    constants.put("crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX", this.sodium.crypto_aead_xchacha20poly1305_ietf_messagebytes_max());
    // constants.put("crypto_kx_PUBLICKEYBYTES", this.sodium.crypto_kx_publickeybytes());
    // constants.put("crypto_kx_SECRETKEYBYTES", this.sodium.crypto_kx_secretkeybytes());
    // constants.put("crypto_kx_SEEDBYTES", this.sodium.crypto_kx_seedbytes());
    // constants.put("crypto_kx_SESSIONKEYBYTES", this.sodium.crypto_kx_sessionkeybytes());
    constants.put("crypto_secretstream_xchacha20poly1305_ABYTES", this.sodium.crypto_secretstream_xchacha20poly1305_abytes());
    constants.put("crypto_secretstream_xchacha20poly1305_HEADERBYTES", this.sodium.crypto_secretstream_xchacha20poly1305_headerbytes());
    constants.put("crypto_secretstream_xchacha20poly1305_KEYBYTES", this.sodium.crypto_secretstream_xchacha20poly1305_keybytes());
    constants.put("crypto_secretstream_xchacha20poly1305_TAGBYTES", 1);
    constants.put("crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX", this.sodium.crypto_secretstream_xchacha20poly1305_messagebytes_max());

    return constants;
  }

  @ReactMethod
  public WritableArray noop(ReadableArray in) {

    byte[] key = ArgumentsEx.toByteArray(in);

    return ArrayUtil.toWritableArray(key);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_generichash_batch(ReadableArray output, ReadableMap batch, ReadableArray key) {
    byte[] state = new byte[(int) this.sodium.crypto_generichash_statebytes()];
    byte[] _key = ArgumentsEx.toByteArray(key);
    sodium.crypto_generichash_init(state, _key, _key.length, output.size());

    int i = 1;
    ReadableMapKeySetIterator ite = batch.keySetIterator();
    while (ite.hasNextKey()) {
      String nextKey = Integer.toString(i++);
      byte[] toHash = ArgumentsEx.toByteArray(batch.getArray(nextKey));
      this.sodium.crypto_generichash_update(state, toHash, toHash.length);
    }

    byte[] result = new byte[(int) this.sodium.crypto_generichash_bytes()];
    byte[] resultBuf = result;
    this.sodium.crypto_generichash_final(state, resultBuf, resultBuf.length);

    return ArrayUtil.toWritableArray(result);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_keygen(ReadableArray k) {

    byte[] key = ArgumentsEx.toByteArray(k);
    this.sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key);

    return ArrayUtil.toWritableArray(key);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray randombytes_buf(ReadableArray in) {

    byte[] buf = ArgumentsEx.toByteArray(in);
    this.sodium.randombytes_buf(buf, buf.length);

    return ArrayUtil.toWritableArray(buf);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_encrypt(ReadableArray c, ReadableArray m, ReadableArray ad, ReadableArray nsec, ReadableArray npub, ReadableArray k) {
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] clen_p = new int[1];

    this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      _c, clen_p,
      _m, m.size(),
      _ad, ad.size(),
      _nsec, _npub, _k);
    
    return ArrayUtil.toWritableArray( Arrays.copyOfRange(_c, 0, clen_p[0] ) );
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_decrypt(ReadableArray m, ReadableArray nsec, ReadableArray c, ReadableArray ad, ReadableArray npub, ReadableArray k) {
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] mlen_p = new int[1];

    this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      _m, mlen_p,
      _nsec,
      _c,  c.size(),
      _ad, ad.size(),
      _npub, _k);
    
    return ArrayUtil.toWritableArray( Arrays.copyOfRange(_m, 0, mlen_p[0] ) );
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_keygen(ReadableArray k) {

    byte[] key = ArgumentsEx.toByteArray(k);
    this.sodium.crypto_secretstream_xchacha20poly1305_keygen(key);

    return ArrayUtil.toWritableArray(key);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_init_push(ReadableArray state, ReadableArray header, ReadableArray k) {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _header = ArgumentsEx.toByteArray(header);
    byte[] _k = ArgumentsEx.toByteArray(k);

    this.sodium.crypto_secretstream_xchacha20poly1305_init_push(_state, _header, _k);
    
    return ArrayUtil.toWritableArray(_state);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_push(ReadableArray state, ReadableArray c, ReadableArray m, ReadableArray ad, ReadableArray tag) {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _tag = ArgumentsEx.toByteArray(tag);
    int[] clen_p = new int[1];

    this.sodium.crypto_secretstream_xchacha20poly1305_push(_state, _c, clen_p, _m, _m.length, _ad, _ad.length, _tag);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
    outputStream.write( _state );
    outputStream.write( Arrays.copyOfRange(_c, 0, clen_p[0] ) ); // put dynamic length entry last

    byte ret[] = outputStream.toByteArray( );

    return ArrayUtil.toWritableArray(ret)
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_init_pull(ReadableArray state, ReadableArray header, ReadableArray k) {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _header = ArgumentsEx.toByteArray(header);
    byte[] _k = ArgumentsEx.toByteArray(k);

    this.sodium.crypto_secretstream_xchacha20poly1305_init_pull(_state, _header, _k);
    
    return ArrayUtil.toWritableArray(_state);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_secretstream_xchacha20poly1305_pull(ReadableArray state, ReadableArray m, ReadableArray tag, ReadableArray c, ReadableArray ad) {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _tag = ArgumentsEx.toByteArray(tag);
    int[] mlen_p = new int[1];
    
    this.sodium.crypto_secretstream_xchacha20poly1305_pull(_state, _m, mlen_p, _tag, _c, _c.length, _ad, _ad.length);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
    outputStream.write( _state );
    outputStream.write( _tag );
    outputStream.write( Arrays.copyOfRange(_m, 0, mlen_p[0] ) ); // put dynamic length entry last

    byte ret[] = outputStream.toByteArray( );

    return ArrayUtil.toWritableArray(ret)
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_scalar_random (ReadableArray r) {
    byte[] _r = ArgumentsEx.toByteArray(r);
  
    this.sodium.crypto_core_ed25519_scalar_random(_r);

    return ArrayUtil.toWritableArray(_r);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_add (ReadableArray r, ReadableArray p, ReadableArray q) {
    byte[] _r = ArgumentsEx.toByteArray(r);
    byte[] _p = ArgumentsEx.toByteArray(p);
    byte[] _q = ArgumentsEx.toByteArray(q);

    this.sodium.crypto_core_ed25519_add(_r, _p, _q);

    return ArrayUtil.toWritableArray(_r);
  }
  
  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_sub (ReadableArray r, ReadableArray p, ReadableArray q) {
    byte[] _r = ArgumentsEx.toByteArray(r);
    byte[] _p = ArgumentsEx.toByteArray(p);
    byte[] _q = ArgumentsEx.toByteArray(q);
  
    this.sodium.crypto_core_ed25519_sub(_r, _p, _q);

    return ArrayUtil.toWritableArray(_r);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_core_ed25519_from_uniform (ReadableArray p, ReadableArray r) {
    byte[] _p = ArgumentsEx.toByteArray(p);
    byte[] _r = ArgumentsEx.toByteArray(r);
  
    this.sodium.crypto_core_ed25519_from_uniform(_p, _r);

    return ArrayUtil.toWritableArray(_p);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_pwhash (ReadableArray out, ReadableArray passwd, ReadableArray salt, int opslimit, int memlimit, int alg) {
    byte[] _out = ArgumentsEx.toByteArray(out);
    byte[] _passwd = ArgumentsEx.toByteArray(passwd);
    byte[] _salt = ArgumentsEx.toByteArray(salt);
  
    int ret = this.sodium.crypto_pwhash(_out, _out.length, _passwd, _passwd.length, _salt, opslimit, memlimit, alg);

    return ArrayUtil.toWritableArray(_out);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519 (ReadableArray q, ReadableArray n, ReadableArray p) {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);
    byte[] _p = ArgumentsEx.toByteArray(p);
  
    this.sodium.crypto_scalarmult_ed25519(_q, _n, _p);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519_noclamp (ReadableArray q, ReadableArray n, ReadableArray p) {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);
    byte[] _p = ArgumentsEx.toByteArray(p);
  
    this.sodium.crypto_scalarmult_ed25519_noclamp(_q, _n, _p);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519_base (ReadableArray q, ReadableArray n) {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);
  
    this.sodium.crypto_scalarmult_ed25519_base(_q, _n);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_scalarmult_ed25519_base_noclamp (ReadableArray q, ReadableArray n) {
    byte[] _q = ArgumentsEx.toByteArray(q);
    byte[] _n = ArgumentsEx.toByteArray(n);
  
    this.sodium.crypto_scalarmult_ed25519_base_noclamp(_q, _n);

    return ArrayUtil.toWritableArray(_q);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_generichash_init (ReadableArray state, ReadableArray key, double outlen) {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _key = ArgumentsEx.toByteArray(key);
  
    this.sodium.crypto_generichash_init(_state, _key, _key.length, (int) outlen);
    return ArrayUtil.toWritableArray(_state);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_generichash_update (ReadableArray state, ReadableArray in) {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _in = ArgumentsEx.toByteArray(in);
  
    this.sodium.crypto_generichash_update(_state, _in, _in.length);

    return ArrayUtil.toWritableArray(_state);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_generichash_final (ReadableArray state, ReadableArray out) {
    byte[] _state = ArgumentsEx.toByteArray(state);
    byte[] _out = ArgumentsEx.toByteArray(out);
  
    this.sodium.crypto_generichash_final(_state, _out, _out.length);

    return ArrayUtil.toWritableArray(_out);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_kdf_keygen (ReadableArray key) {
    byte[] _key = ArgumentsEx.toByteArray(key);
  
    this.sodium.crypto_kdf_keygen(_key);

    return ArrayUtil.toWritableArray(_key);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_kdf_derive_from_key (ReadableArray subkey, int subkey_id, ReadableArray ctx, ReadableArray key) {
    byte[] _subkey = ArgumentsEx.toByteArray(subkey);
    byte[] _ctx = ArgumentsEx.toByteArray(ctx);
    byte[] _key = ArgumentsEx.toByteArray(key);
  
    this.sodium.crypto_kdf_derive_from_key(_subkey, _subkey.length, subkey_id, _ctx, _key);

    return ArrayUtil.toWritableArray(_subkey);
  }
}
