-- |
-- Module      : Crypto.PubKey.RSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.PubKey.RSA
    ( Error(..)
    , PublicKey(..)
    , PrivateKey(..)
    , generate
    ) where

import Crypto.Random.API
import Crypto.Types.PubKey.RSA
import Crypto.Number.ModArithmetic (inverse)
import Crypto.Number.Prime (generatePrime)
import Crypto.PubKey.RSA.Types
import Data.Maybe (fromJust)

-- | generate a public key and private key with p and q.
--
-- p and q need to be distinct primes numbers.
--
-- e need to be coprime to (p-1)*(q-1). a small hamming weight results in better performance.
-- 0x10001 is a popular choice. 3 is popular as well, but proven to not be as secure for some cases.
generateWith :: (Integer, Integer) -> Int -> Integer -> Maybe (PublicKey, PrivateKey)
generateWith (p,q) size e = (pub,priv)
    where n   = p*q
          phi = (p-1)*(q-1)
          d   = fromJust $ inverse e phi -- e and phi need to be coprime
          pub = PublicKey { public_size = size
                          , public_n    = n
                          , public_e    = e
                          }
          priv = PrivateKey { private_pub  = pub
                            , private_d    = d
                            , private_p    = p
                            , private_q    = q
                            , private_dP   = d `mod` (p-1)
                            , private_dQ   = d `mod` (q-1)
                            , private_qinv = fromJust $ inverse q p -- q and p are coprime, so fromJust is safe.
                            }

-- | generate a pair of (private, public) key of size in bytes.
generate :: CPRG g => g -> Int -> Integer -> ((PublicKey, PrivateKey), g)
generate rng size e = do
    let (pq, rng') = generatePQ rng
     in (generateWith pq size e, rng')
    where
        generatePQ g =
            let (p, g')  = generatePrime g (8 * (size `div` 2))
                (q, g'') = generateQ p g'
             in ((p,q), g'')
        generateQ p h =
            let (q, h') = generatePrime h (8 * (size - (size `div` 2)))
             in if p == q then generateQ p h' else (q, h')
