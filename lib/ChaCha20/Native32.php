<?php

namespace ChaCha20;

class Native32
{
    function encrypt(Context $ctx, $message)
    {
        $rk = $ctx->rk;

        $messageLen = strlen($message);
        $keyStream = $ctx->buffer;

        if ($keyStream) {
            $offset = strlen($keyStream);
            $messageLen -= $offset;
            $out = $message ^ $keyStream;
        }
        else {
            $offset = 0;
            $out = '';
        }

        $messageRemainder = $messageLen % 64;
        $blocks = ($messageLen >> 6) + ($messageRemainder > 0);

        while ($blocks--) {
            list($k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7, $k8, $k9, $k10, $k11, $k12, $k13, $k14, $k15) = $rk;

            $i = 10;
            while ($i--) {
                $k0 = $k0 +  $k4; $c = $k12 ^ $k0; $k12 = ($c << 16) | $c >> 16 & 0xffff;
                $k8 = $k8 + $k12; $c =  $k4 ^ $k8;  $k4 = ($c << 12) | $c >> 20 & 0xfff;
                $k0 = $k0 +  $k4; $c = $k12 ^ $k0; $k12 = ($c <<  8) | $c >> 24 & 0xff;
                $k8 = $k8 + $k12; $c =  $k4 ^ $k8;  $k4 = ($c <<  7) | $c >> 25 & 0x7f;

                $k1 = $k1 +  $k5; $c = $k13 ^ $k1; $k13 = ($c << 16) | $c >> 16 & 0xffff;
                $k9 = $k9 + $k13; $c =  $k5 ^ $k9;  $k5 = ($c << 12) | $c >> 20 & 0xfff;
                $k1 = $k1 +  $k5; $c = $k13 ^ $k1; $k13 = ($c <<  8) | $c >> 24 & 0xff;
                $k9 = $k9 + $k13; $c =  $k5 ^ $k9;  $k5 = ($c <<  7) | $c >> 25 & 0x7f;

                $k2  =  $k2 +  $k6; $c = $k14 ^  $k2; $k14 = ($c << 16) | $c >> 16 & 0xffff;
                $k10 = $k10 + $k14; $c =  $k6 ^ $k10;  $k6 = ($c << 12) | $c >> 20 & 0xfff;
                $k2  =  $k2 +  $k6; $c = $k14 ^  $k2; $k14 = ($c <<  8) | $c >> 24 & 0xff;
                $k10 = $k10 + $k14; $c =  $k6 ^ $k10;  $k6 = ($c <<  7) | $c >> 25 & 0x7f;

                $k3  =  $k3 +  $k7; $c = $k15 ^  $k3; $k15 = ($c << 16) | $c >> 16 & 0xffff;
                $k11 = $k11 + $k15; $c =  $k7 ^ $k11;  $k7 = ($c << 12) | $c >> 20 & 0xfff;
                $k3  =  $k3 +  $k7; $c = $k15 ^  $k3; $k15 = ($c <<  8) | $c >> 24 & 0xff;
                $k11 = $k11 + $k15; $c =  $k7 ^ $k11;  $k7 = ($c <<  7) | $c >> 25 & 0x7f;

                $k0  =  $k0 +  $k5; $c = $k15 ^  $k0; $k15 = ($c << 16) | $c >> 16 & 0xffff;
                $k10 = $k10 + $k15; $c =  $k5 ^ $k10;  $k5 = ($c << 12) | $c >> 20 & 0xfff;
                $k0  =  $k0 +  $k5; $c = $k15 ^  $k0; $k15 = ($c <<  8) | $c >> 24 & 0xff;
                $k10 = $k10 + $k15; $c =  $k5 ^ $k10;  $k5 = ($c <<  7) | $c >> 25 & 0x7f;

                $k1  =  $k1 +  $k6; $c = $k12 ^  $k1; $k12 = ($c << 16) | $c >> 16 & 0xffff;
                $k11 = $k11 + $k12; $c =  $k6 ^ $k11;  $k6 = ($c << 12) | $c >> 20 & 0xfff;
                $k1  =  $k1 +  $k6; $c = $k12 ^  $k1; $k12 = ($c <<  8) | $c >> 24 & 0xff;
                $k11 = $k11 + $k12; $c =  $k6 ^ $k11;  $k6 = ($c <<  7) | $c >> 25 & 0x7f;

                $k2 = $k2 +  $k7; $c = $k13 ^ $k2; $k13 = ($c << 16) | $c >> 16 & 0xffff;
                $k8 = $k8 + $k13; $c =  $k7 ^ $k8;  $k7 = ($c << 12) | $c >> 20 & 0xfff;
                $k2 = $k2 +  $k7; $c = $k13 ^ $k2; $k13 = ($c <<  8) | $c >> 24 & 0xff;
                $k8 = $k8 + $k13; $c =  $k7 ^ $k8;  $k7 = ($c <<  7) | $c >> 25 & 0x7f;

                $k3 = $k3 +  $k4; $c = $k14 ^ $k3; $k14 = ($c << 16) | $c >> 16 & 0xffff;
                $k9 = $k9 + $k14; $c =  $k4 ^ $k9;  $k4 = ($c << 12) | $c >> 20 & 0xfff;
                $k3 = $k3 +  $k4; $c = $k14 ^ $k3; $k14 = ($c <<  8) | $c >> 24 & 0xff;
                $k9 = $k9 + $k14; $c =  $k4 ^ $k9;  $k4 = ($c <<  7) | $c >> 25 & 0x7f;
            }

            $keyStream = pack('V16',
                $k0 + $rk[0],
                $k1 + $rk[1],
                $k2 + $rk[2],
                $k3 + $rk[3],
                $k4 + $rk[4],
                $k5 + $rk[5],
                $k6 + $rk[6],
                $k7 + $rk[7],
                $k8 + $rk[8],
                $k9 + $rk[9],
                $k10 + $rk[10],
                $k11 + $rk[11],
                $k12 + $rk[12],
                $k13 + $rk[13],
                $k14 + $rk[14],
                $k15 + $rk[15]
            );

            $out .= substr($message, $offset, 64) ^ $keyStream;

            $rk[12] = $rk[12] + 1;
            if (!$rk[12]) {
                $rk[13] = $rk[13] + 1;
            }

            $offset += 64;
        }

        if ($messageRemainder) {
            $ctx->buffer = substr($keyStream, $messageRemainder);
        }
        else {
            $ctx->buffer = '';
        }

        $ctx->rk = $rk;

        return $out;
    }

    public function decrypt(Context $ctx, $message)
    {
        return $this->encrypt($ctx, $message);
    }
}
