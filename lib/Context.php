<?php

namespace ChaCha20;

class Context
{
    public $state;
    public $buffer = '';

    function __construct($key, $nonce)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \LengthException('Key must be a 256-bit string');
        }

        if (!is_string($nonce) || strlen($nonce) !== 12) {
            throw new \LengthException('Nonce must be a 96-bit string');
        }

        $this->state = array_values(unpack('V16', "expand 32-byte k$key\0\0\0\0$nonce"));
    }
}
