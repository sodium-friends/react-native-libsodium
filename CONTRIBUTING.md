# Contributing

The current library only exposes a subset of the functions provided by Frank Denis' [Libsodium](https://libsodium.gitbook.io/doc/) library. Exposing additional methods is quite doable and the following guide outlines how to do so. Once finished, please submit a PR so we can keep this library up to date!

## API Format

This library is designed to be a drop in replacement for preexisting [libdsodium ports](https://github.com/sodium-friends/) and therefore must have API parity. Make sure to consult the [API docs](https://sodium-friends.github.io/docs/docs/api) to see find the signatures the native modules we export to React Native should have.

#### Export Synchronous Methods

All methods should exported as synchronous methods:

in Java, functions exported from [`SodiumModule.java`](./android/src/main/java/com/reactnativelibsodium/rn/SodiumModule.java) should use
```java
@ReactMethod(isBlockingSynchronousMethod = true)
```

in Objective-C, functions exported from our [module](./ios/RCTSodium/RCTSodium.m) should use the `RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD` macro provided by `RCTBridgeModule.h`.

#### Returning Multiple Buffers

Sometimes we need to return multiple buffers to JS. React Native does not support returning nested `Array`s or `Map`s of `Array`s, so in order to achieve this, we copy the buffers consecutively into a single buffer. The process is straightforward and is demonstrated in each language by the `crypto_secretstream_xchacha20poly1305` methods.

Only one variable length return buffer is supported and should be placed last, however, length prefixing would allow for multiple if the usecase arises. If you end up implementing this, we'd love to merge it so definitely submit a PR!

#### Errors

If you encounter a libsodium error that doesn't have a corresponding error type (eg. `ERR_BAD_KEY`), you can add extend the error types in the native modules with the error you need. These should be string literals indicating the fault to the user.

## Android

In order to be able to call functions from the native C library in React-Native, we must make bindings from the Native language of our target platforms, Java on Android and Objective-C/Swift on iOS, to the prebuilt dynamic library compiled from the C library.

These bindings may be found [here for [iOS](./ios/RCTSodium/RCTSodium.m) and .

### JNI

Our JNI [bindings](./android/src/main/cpp/sodium-jni.c) are written in C++ and accessed via the interface defined in [SodiumJNI.java](./android/src/main/java/com/reactnativelibsodium/jni/SodiumJNI.java).

For most methods, bindings for new methods can easily be adapted from the existing methods. Inputs are typically received from Java as either `jbyteArray` for `Buffers`/`Uint8Arrays`, or `jint` for `Numbers`. When libsodium expects a pointer, eg. `size_t *` for writing a buffer length to, the appropriate JNI type is a `jintArray` and cast to the correct pointer type, see `sodium_pad`/`sodium_unpad` for an example.

#### Buffers

Libsodium mostly operates on memory so buffers are the most common argument type. Buffers will be passed as `jbyteAray` and are handled in one of two ways, depending on if the memory is returned or not.

For memory that is only consumed and not returned to java, helpers are provided: `as_[const_][unsigned_]char_array`, eg.:

```c
unsigned char *m = as_unsigned_char_array(jenv, j_m);
```

Returned memory must be handled differently so that Java may access the returned data:

```c
// accepting memory, the correct types may be found from the libsodium headers
unsigned char *c = (unsigned char *) (*jenv)->GetByteArrayElements(jenv, j_c, 0);

/*
  rest of function
*/

// returning memory
(*jenv)->ReleaseByteArrayElements(jenv, j_c, (jbyte *) c, 0);
```

#### Lengths

For variable length results, libsodium takes a pointer argument to which it writes the number of bytes written to the return buffer. These arguments should be accepted to the function as `jintArray j_arglen_p` and handled like so:

```c
// accepting memory, the type should alwasy be unsigned long long *
unsigned long long *clen_p = (unsigned long long *) (*jenv)->GetIntArrayElements(jenv, j_clen_p, 0); 

/*
  rest of function
*/

// returning memory
(*jenv)->ReleaseIntArrayElements(jenv, j_clen_p, (jint *) clen_p, 0);
```

#### Numbers

Numbers may simply be passed as `jint`s and passed directly to the libsodium function.

#### Compiler warnings

`npx react-native run-android` shall output any compiler warnings or errors, usually due to incompatible pointer types. You should go through and make sure each has been address so that there are no compiler warnings. Note, this __does not__ guarantee the function shall run correctly.

### React-Native

Once we have the JNI bindings, we need create a module exposing these bindings to React Native. The React Native [docs](https://reactnative.dev/docs/native-modules-android) describe this process in general. Here, though, we are only concerned with extending [SodiumModule.java](./android/src/main/java/com/reactnativelibsodium/rn/SodiumModule.java).

#### Argument Types

React Native only exposes certain [argument types](https://reactnative.dev/docs/native-modules-android#argument-types), none of which allow for memory to be shared between the JavaScript runtime and the native module. Therefore JS `Number` arguments are taken as type `int` data is passed to the Native Modules using `Array`s (other libraries often use `String`s, `Array`s were chosen for more efficient conversion from to and from `Uint8Array`/`ByteArray`s, feel free to open an issue if you feel otherwise).

In Java, this means buffer arguments are expected as [`ReadableArray`s](https://github.com/facebook/react-native/blob/master/ReactAndroid/src/main/java/com/facebook/react/bridge/ReadableArray.java) and the return type should be [`WritableArray`](https://github.com/facebook/react-native/blob/master/ReactAndroid/src/main/java/com/facebook/react/bridge/WritableArray.java).

The resulting signature looks something like this:
```Java
  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray crypto_aead_xchacha20poly1305_ietf_encrypt(ReadableArray c, int tag, ...) {
```

Various [helpers](./android/src/main/java/com/reactnativelibsodium/helpers) have been provided for correctly formatting arguments or return values. The existing bindings may be used as reference for their usage, please make sure to bound check the inputs where needed.

#### Exporting Constants

Constants should be exported to React Native at the top of the module file. You can refer to how this is currently done and extend the current exports. Since SWIG generates the bindings before referring to dynamic library, the values of constants are not known up front and must be accessed at runtime by their respective call functions.

## iOS

Since the underlying language is in C, Obj-C bindings are chosen over Swift bindings as this makes it easier to cast pointers to the types expected by libsodium's functions.

### Objective-C

Unlike the Java bindings, these have to be witten by hand. [Macros](./ios/RCTSodium/RCTSodium.m) are provided to make this as easy as possible. The libsodium [docs](https://libsodium.gitbook.io/doc/) should be referred to for the relevant function signatures. Consult the macro definitions to find the relevant one for each argument and be sure the bounds are checked where necessary!

The existing methods should provide a good reference, however, if you encounter any troubles feel free to open and issue or comment in the discussions.

#### Argument Types

Buffer arguments are passed from JS as `Array`s and should be received in Obj-C as `NSArray`s (for rationale, see Java section above) and argumenst passed from JS as `Number`s should be received as `NSNumber`s.

Macros are provided copy the data into buffers and return C pointers of the desired type. In the case where libsodium expects a pointer to a libsodium type, eg. `crypto_generichash_state *`, you should derive an `unsigned char *` from the argument and then cast to the desired libsodium type. You can `crypto_generichash` methods.

#### Exporting Constants

Constants should be exported to React Native at the top of the module file. You can refer to how this is currently done and extend the current exports. Some constants, particularly struct sizes, cannot be known at compile time and therefore must be hardcoded.

## JavaScript

Now that we have native bindings to our C functions exposed in React Native, we can update our JavaScript wrapper found in [index.js](./index.js).

Most of the work is done in our native code, so these are quite simple: use the provided map function to format arguments and pass them to the native function. The return result should be checked for errors (errors always return a `String`).

## Tests

Once you have made the bindings, please port the corresponding test from [sodium-test](https://github.com/sodium-friends/sodium-test).

Thank you!

