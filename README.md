ChaCha20 in PHP
===============

This library contains a pure PHP implementation of the ChaCha20 encryption algorithm.

The library has been written to be high performance (relative to PHP), not pretty. It obviously doesn't perform anywhere close to a native implementation.

### Usage:

Remember that *a nonce must not be used more than once for a particular key*

```
$chacha20 = new ChaCha20\Cipher;
$encCtx = $chacha20->init($key, $nonce);
$decCtx = $chacha20->init($key, $nonce);

$cipherText = $chacha20->encrypt($encCtx, $message);
$plainText = $chacha20->decrypt($decCtx, $cipherText);
```

The `Context` object maintains the current state of the algorithm, so that it can be used in a streaming scenario. Therefore an application performing simultaneous encryption and decryption will need to main two contexts.

The `decrypt` method is an alias of the `encrypt` method, and exists only to indicate intent.

Seek operations can be performed on the keystream by calling the `setCounter` method, where the count is in 64-byte blocks.
