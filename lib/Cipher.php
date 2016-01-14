<?php declare(strict_types = 1);

namespace ChaCha20;

class Cipher
{
    function init(string $key, string $nonce): Context
    {
        if (strlen($key) !== 32) {
            throw new \LengthException('Key must be a 256-bit string');
        }

        if (strlen($nonce) !== 12) {
            throw new \LengthException('Nonce must be a 96-bit string');
        }

        $ctx = new Context();
        $ctx->state = array_values(unpack('V16', "expand 32-byte k$key\0\0\0\0$nonce"));

        return $ctx;
    }

    function encrypt(Context $ctx, string $message): string
    {
        $state = $ctx->state;

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
            list($s00, $s01, $s02, $s03, $s04, $s05, $s06, $s07, $s08, $s09, $s10, $s11, $s12, $s13, $s14, $s15) = $state;

            $i = 10;
            while ($i--) {
                $s04 = ((($c = $s04 ^ ($s08 += ($s12 = (((
                          $c = $s12 ^ ($s00 += ($s04 = (((
                          $c = $s04 ^ ($s08 += ($s12 = (((
                          $c = $s12 ^ ($s00 +=  $s04) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $s05 = ((($c = $s05 ^ ($s09 += ($s13 = (((
                          $c = $s13 ^ ($s01 += ($s05 = (((
                          $c = $s05 ^ ($s09 += ($s13 = (((
                          $c = $s13 ^ ($s01 +=  $s05) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $s06 = ((($c = $s06 ^ ($s10 += ($s14 = (((
                          $c = $s14 ^ ($s02 += ($s06 = (((
                          $c = $s06 ^ ($s10 += ($s14 = (((
                          $c = $s14 ^ ($s02 +=  $s06) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $s07 = ((($c = $s07 ^ ($s11 += ($s15 = (((
                          $c = $s15 ^ ($s03 += ($s07 = (((
                          $c = $s07 ^ ($s11 += ($s15 = (((
                          $c = $s15 ^ ($s03 +=  $s07) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $s05 = ((($c = $s05 ^ ($s10 += ($s15 = (((
                          $c = $s15 ^ ($s00 += ($s05 = (((
                          $c = $s05 ^ ($s10 += ($s15 = (((
                          $c = $s15 ^ ($s00 +=  $s05) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $s06 = ((($c = $s06 ^ ($s11 += ($s12 = (((
                          $c = $s12 ^ ($s01 += ($s06 = (((
                          $c = $s06 ^ ($s11 += ($s12 = (((
                          $c = $s12 ^ ($s01 +=  $s06) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $s07 = ((($c = $s07 ^ ($s08 += ($s13 = (((
                          $c = $s13 ^ ($s02 += ($s07 = (((
                          $c = $s07 ^ ($s08 += ($s13 = (((
                          $c = $s13 ^ ($s02 +=  $s07) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;

                $s04 = ((($c = $s04 ^ ($s09 += ($s14 = (((
                          $c = $s14 ^ ($s03 += ($s04 = (((
                          $c = $s04 ^ ($s09 += ($s14 = (((
                          $c = $s14 ^ ($s03 +=  $s04) & 0xffffffff) << 16) & 0xffffffff) | $c >> 16))
                                                      & 0xffffffff) << 12) & 0xffffffff) | $c >> 20))
                                                      & 0xffffffff) <<  8) & 0xffffffff) | $c >> 24))
                                                      & 0xffffffff) <<  7) & 0xffffffff) | $c >> 25;
            }

            $keyStream = pack('V16',
                $s00 + $state[ 0],
                $s01 + $state[ 1],
                $s02 + $state[ 2],
                $s03 + $state[ 3],
                $s04 + $state[ 4],
                $s05 + $state[ 5],
                $s06 + $state[ 6],
                $s07 + $state[ 7],
                $s08 + $state[ 8],
                $s09 + $state[ 9],
                $s10 + $state[10],
                $s11 + $state[11],
                $s12 + $state[12],
                $s13 + $state[13],
                $s14 + $state[14],
                $s15 + $state[15]
            );

            $out .= substr($message, $offset, 64) ^ $keyStream;

            $state[12] = $state[12] + 1 & 0xffffffff;
            if (!$state[12]) {
                throw new \OverflowException('Counter overflowed upper bound');
            }

            $offset += 64;
        }

        if ($messageRemainder) {
            $ctx->buffer = substr($keyStream, $messageRemainder);
        }
        else {
            $ctx->buffer = '';
        }

        $ctx->state = $state;

        return $out;
    }

    public function decrypt(Context $ctx, string $message): string
    {
        return $this->encrypt($ctx, $message);
    }

    public function setCounter(Context $ctx, int $counter)
    {
        if ($counter < 0 || $counter > 0xffffffff) {
            throw new \InvalidArgumentException('Counter must be 32-bit positive integer');
        }

        $ctx->state[12] = $counter;
        $ctx->buffer = '';
    }
}
