<?php

namespace ChaCha20;

class Native64
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
                $k0 = $k0 +  $k4 & 0xffffffff; $c = $k12 ^ $k0; $k12 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k8 = $k8 + $k12 & 0xffffffff; $c =  $k4 ^ $k8;  $k4 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k0 = $k0 +  $k4 & 0xffffffff; $c = $k12 ^ $k0; $k12 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k8 = $k8 + $k12 & 0xffffffff; $c =  $k4 ^ $k8;  $k4 = (($c <<  7) & 0xffffffff) | $c >> 25;

                $k1 = $k1 +  $k5 & 0xffffffff; $c = $k13 ^ $k1; $k13 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k9 = $k9 + $k13 & 0xffffffff; $c =  $k5 ^ $k9;  $k5 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k1 = $k1 +  $k5 & 0xffffffff; $c = $k13 ^ $k1; $k13 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k9 = $k9 + $k13 & 0xffffffff; $c =  $k5 ^ $k9;  $k5 = (($c <<  7) & 0xffffffff) | $c >> 25;
                
                $k2  =  $k2 +  $k6 & 0xffffffff; $c = $k14 ^  $k2; $k14 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k10 = $k10 + $k14 & 0xffffffff; $c =  $k6 ^ $k10;  $k6 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k2  =  $k2 +  $k6 & 0xffffffff; $c = $k14 ^  $k2; $k14 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k10 = $k10 + $k14 & 0xffffffff; $c =  $k6 ^ $k10;  $k6 = (($c <<  7) & 0xffffffff) | $c >> 25;
                
                $k3  =  $k3 +  $k7 & 0xffffffff; $c = $k15 ^  $k3; $k15 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k11 = $k11 + $k15 & 0xffffffff; $c =  $k7 ^ $k11;  $k7 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k3  =  $k3 +  $k7 & 0xffffffff; $c = $k15 ^  $k3; $k15 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k11 = $k11 + $k15 & 0xffffffff; $c =  $k7 ^ $k11;  $k7 = (($c <<  7) & 0xffffffff) | $c >> 25;

                $k0  =  $k0 +  $k5 & 0xffffffff; $c = $k15 ^  $k0; $k15 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k10 = $k10 + $k15 & 0xffffffff; $c =  $k5 ^ $k10;  $k5 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k0  =  $k0 +  $k5 & 0xffffffff; $c = $k15 ^  $k0; $k15 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k10 = $k10 + $k15 & 0xffffffff; $c =  $k5 ^ $k10;  $k5 = (($c <<  7) & 0xffffffff) | $c >> 25;

                $k1  =  $k1 +  $k6 & 0xffffffff; $c = $k12 ^  $k1; $k12 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k11 = $k11 + $k12 & 0xffffffff; $c =  $k6 ^ $k11;  $k6 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k1  =  $k1 +  $k6 & 0xffffffff; $c = $k12 ^  $k1; $k12 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k11 = $k11 + $k12 & 0xffffffff; $c =  $k6 ^ $k11;  $k6 = (($c <<  7) & 0xffffffff) | $c >> 25;
                
                $k2 = $k2 +  $k7 & 0xffffffff; $c = $k13 ^ $k2; $k13 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k8 = $k8 + $k13 & 0xffffffff; $c =  $k7 ^ $k8;  $k7 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k2 = $k2 +  $k7 & 0xffffffff; $c = $k13 ^ $k2; $k13 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k8 = $k8 + $k13 & 0xffffffff; $c =  $k7 ^ $k8;  $k7 = (($c <<  7) & 0xffffffff) | $c >> 25;
                
                $k3 = $k3 +  $k4 & 0xffffffff; $c = $k14 ^ $k3; $k14 = (($c << 16) & 0xffffffff) | $c >> 16;
                $k9 = $k9 + $k14 & 0xffffffff; $c =  $k4 ^ $k9;  $k4 = (($c << 12) & 0xffffffff) | $c >> 20;
                $k3 = $k3 +  $k4 & 0xffffffff; $c = $k14 ^ $k3; $k14 = (($c <<  8) & 0xffffffff) | $c >> 24;
                $k9 = $k9 + $k14 & 0xffffffff; $c =  $k4 ^ $k9;  $k4 = (($c <<  7) & 0xffffffff) | $c >> 25;
            }
            
            $keyStream = pack('V16',
                $k0  + $rk[0],
                $k1  + $rk[1],
                $k2  + $rk[2],
                $k3  + $rk[3],
                $k4  + $rk[4],
                $k5  + $rk[5],
                $k6  + $rk[6],
                $k7  + $rk[7],
                $k8  + $rk[8],
                $k9  + $rk[9],
                $k10 + $rk[10],
                $k11 + $rk[11],
                $k12 + $rk[12],
                $k13 + $rk[13],
                $k14 + $rk[14],
                $k15 + $rk[15]
            );

            $out .= substr($message, $offset, 64) ^ $keyStream;

            $rk[12] = $rk[12] + 1 & 0xffffffff;
            if (!$rk[12]) {
                $rk[13] = $rk[13] + 1 & 0xffffffff;
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
