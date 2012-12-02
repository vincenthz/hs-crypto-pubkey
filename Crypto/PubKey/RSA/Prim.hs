-- |
-- Module      : Crypto.PubKey.RSA.Prim
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.PubKey.RSA.Prim
    ( dpSlow
    , dpFast
    , ep
    ) where

import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import Crypto.Types.PubKey.RSA
import Crypto.PubKey.RSA.Types
import Crypto.Number.ModArithmetic (exponantiation, inverse)
import Crypto.Number.Serialize (os2ip, i2ospOf_)

{- dpSlow computes the decrypted message not using any precomputed cache value.
   only n and d need to valid. -}
dpSlow :: Integer -> PrivateKey -> ByteString -> ByteString
dpSlow _ pk c = i2ospOf_ (private_size pk) $ expmod (os2ip c) (private_d pk) (private_n pk)

{- dpFast computes the decrypted message more efficiently if the
   precomputed private values are available. mod p and mod q are faster
   to compute than mod pq -}
dpFast :: Integer -> PrivateKey -> ByteString -> ByteString
dpFast r pk c = i2ospOf_ (private_size pk) (multiplication rm1 (m2 + h * (private_q pk)) (private_n pk))
    where
        re  = expmod r (public_e $ private_pub pk) (private_n pk)
        rm1 = fromJust $ inverse r (private_n pk)
        iC  = multiplication re (os2ip c) (private_n pk)
        m1  = expmod iC (private_dP pk) (private_p pk)
        m2  = expmod iC (private_dQ pk) (private_q pk)
        h   = ((private_qinv pk) * (m1 - m2)) `mod` (private_p pk)

ep :: PublicKey -> ByteString -> ByteString
ep pk m = i2ospOf_ (public_size pk) $ expmod (os2ip m) (public_e pk) (public_n pk)

expmod :: Integer -> Integer -> Integer -> Integer
expmod = exponantiation

-- | multiply 2 integers in Zm only performing the modulo operation if necessary
multiplication :: Integer -> Integer -> Integer -> Integer
multiplication a b m
             | a == 1    = b
             | b == 1    = a
             | otherwise = (a * b) `mod` m
