<?php

namespace ChaCha20;

class Context
{
    public $rk;
    public $buffer = '';

    function __construct($key, $iv)
    {
        if (strlen($iv) !== 8) {
            throw new \LengthException('IV must be 8 bytes');
        }

        switch (strlen($key)) {
            case 32:
                $this->rk = array_values(unpack('V16', "expand 32-byte k$key\0\0\0\0\0\0\0\0$iv"));
                break;
            case 16:
                $this->rk = array_values(unpack('V16', "expand 16-byte k$key$key\0\0\0\0\0\0\0\0$iv"));
                break;
            default:
                throw new \LengthException('Key must be 16 or 32 bytes');
        }
    }
}
