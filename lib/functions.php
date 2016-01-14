<?php

namespace ChaCha20;

if (!extension_loaded('chacha20')) {
    function encrypt(string $key, string $nonce, string $plaintext): string
    {
        $cipher = new Cipher();
        $context = $cipher->init($key, $nonce);
        $ciphertext = $cipher->encrypt($context, $plaintext);
        return $ciphertext;
    }

    function decrypt(string $key, string $nonce, string $ciphertext): string
    {
        $cipher = new Cipher();
        $context = $cipher->init($key, $nonce);
        $plaintext = $cipher->decrypt($context, $ciphertext);
        return $plaintext;
    }
}
