<?php

namespace ChaCha20;

if (!extension_loaded('chacha20')) {
    function encrypt($key, $nonce, $plaintext)
    {
        $cipher = new Cipher();
        $context = $cipher->init($key, $nonce);
        $ciphertext = $cipher->encrypt($context, $plaintext);
        return $ciphertext;
    }

    function decrypt($key, $nonce, $ciphertext)
    {
        $cipher = new Cipher();
        $context = $cipher->init($key, $nonce);
        $plaintext = $cipher->decrypt($context, $ciphertext);
        return $plaintext;
    }
}
