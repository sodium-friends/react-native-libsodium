package com.reactnativelibsodium;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.Callback;

import java.nio.*;
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
import com.local.jni.Sodium;
import com.local.jni.NaCl;
import com.reactnativelibsodium.helpers.*;

public class LibsodiumModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;

  private Sodium sodium = NaCl.sodium();

  public LibsodiumModule(ReactApplicationContext reactContext) {
      super(reactContext);
      this.reactContext = reactContext;
  }

  @Override
  public String getName() {
      return "Libsodium";
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

  @ReactMethod
  public void randombytes_buf(ReadableArray in, Promise promise) {

    byte[] buf = ArgumentsEx.toByteArray(in);
    this.sodium.randombytes_buf(buf, buf.length);

    promise.resolve(ArrayUtil.toWritableArray(buf));
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_encrypt(ReadableArray c, ReadableArray m, ReadableArray ad, ReadableArray nsec, ReadableArray npub, ReadableArray k, Promise promise) {
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] c_len = new int[1];

    this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      _c, c_len,
      _m, m.size(),
      _ad, ad.size(),
      _nsec, _npub, _k);
    
    return ArrayUtil.toWritableArray(_c);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_decrypt(ReadableArray m, ReadableArray nsec, ReadableArray c, ReadableArray ad, ReadableArray npub, ReadableArray k) {
    byte[] _m = ArgumentsEx.toByteArray(m);
    byte[] _nsec = ArgumentsEx.toByteArray(nsec);
    byte[] _c = ArgumentsEx.toByteArray(c);
    byte[] _ad = ArgumentsEx.toByteArray(ad);
    byte[] _npub = ArgumentsEx.toByteArray(npub);
    byte[] _k = ArgumentsEx.toByteArray(k);
    int[] m_len = new int[0];

    this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      _m, m_len,
      _nsec,
      _c,  c.size(),
      _ad, ad.size(),
      _npub, _k);
    
    return ArrayUtil.toWritableArray(_m);
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
  
  // public void sodium_memcmp (String, Promise promise) {

  // }

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
