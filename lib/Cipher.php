<?php

namespace ChaCha20;

class Cipher
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

        while ($blocks-- > 0) {
            list($k00, $k01, $k02, $k03, $k04, $k05, $k06, $k07, $k08, $k09, $k10, $k11, $k12, $k13, $k14, $k15) = $rk;

            $i = 10;
            while ($i--) {
                $k04 = ((($c = $k04 ^ ($k08 += ($k12 = (((
                          $c = $k12 ^ ($k00 += ($k04 = (((
                          $c = $k04 ^ ($k08 += ($k12 = (((
                          $c = $k12 ^ ($k00 +=  $k04) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $k05 = ((($c = $k05 ^ ($k09 += ($k13 = (((
                          $c = $k13 ^ ($k01 += ($k05 = (((
                          $c = $k05 ^ ($k09 += ($k13 = (((
                          $c = $k13 ^ ($k01 +=  $k05) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $k06 = ((($c = $k06 ^ ($k10 += ($k14 = (((
                          $c = $k14 ^ ($k02 += ($k06 = (((
                          $c = $k06 ^ ($k10 += ($k14 = (((
                          $c = $k14 ^ ($k02 +=  $k06) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $k07 = ((($c = $k07 ^ ($k11 += ($k15 = (((
                          $c = $k15 ^ ($k03 += ($k07 = (((
                          $c = $k07 ^ ($k11 += ($k15 = (((
                          $c = $k15 ^ ($k03 +=  $k07) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $k05 = ((($c = $k05 ^ ($k10 += ($k15 = (((
                          $c = $k15 ^ ($k00 += ($k05 = (((
                          $c = $k05 ^ ($k10 += ($k15 = (((
                          $c = $k15 ^ ($k00 +=  $k05) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $k06 = ((($c = $k06 ^ ($k11 += ($k12 = (((
                          $c = $k12 ^ ($k01 += ($k06 = (((
                          $c = $k06 ^ ($k11 += ($k12 = (((
                          $c = $k12 ^ ($k01 +=  $k06) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $k07 = ((($c = $k07 ^ ($k08 += ($k13 = (((
                          $c = $k13 ^ ($k02 += ($k07 = (((
                          $c = $k07 ^ ($k08 += ($k13 = (((
                          $c = $k13 ^ ($k02 +=  $k07) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $k04 = ((($c = $k04 ^ ($k09 += ($k14 = (((
                          $c = $k14 ^ ($k03 += ($k04 = (((
                          $c = $k04 ^ ($k09 += ($k14 = (((
                          $c = $k14 ^ ($k03 +=  $k04) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;
            }

            $keyStream = pack('V16',
                $k00 + $rk[ 0],
                $k01 + $rk[ 1],
                $k02 + $rk[ 2],
                $k03 + $rk[ 3],
                $k04 + $rk[ 4],
                $k05 + $rk[ 5],
                $k06 + $rk[ 6],
                $k07 + $rk[ 7],
                $k08 + $rk[ 8],
                $k09 + $rk[ 9],
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

    public function setCounter(Context $ctx, $counter)
    {
        $ctx->rk[12] = $counter & 0xffffffff;
        $ctx->rk[13] = ($counter >> 32) & 0xffffffff;
    }
}
