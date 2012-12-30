-- |
-- Module      : Crypto.PubKey.DSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--

module Crypto.PubKey.DSA
    ( Params
    , Signature
    , PublicKey(..)
    , PrivateKey(..)
    , sign
    , verify
    ) where

import Crypto.Random.API
import Data.Maybe
import Data.ByteString (ByteString)
import Crypto.Number.ModArithmetic (exponantiation, inverse)
import Crypto.Number.Serialize
import Crypto.Number.Generate
import Crypto.Types.PubKey.DSA
import Crypto.PubKey.HashDescr


{-| sign message using the private key. -}
sign :: CPRG g => g -> HashFunction -> PrivateKey -> ByteString -> (Signature, g)
sign rng hash pk m =
    let (k, rng') = generateMax rng q
        kinv      = fromJust $ inverse k q
        r         = expmod g k p `mod` q
        s         = (kinv * (hm + x * r)) `mod` q
    -- Recalculate the signature in the unlikely case that r = 0 or s = 0
     in if r == 0 || s == 0
                then sign rng' hash pk m
                else ((r, s), rng')
    where
        (p,g,q)   = private_params pk
        x         = private_x pk
        hm        = os2ip $ hash m

-- | verify a bytestring using the public key.
verify :: HashFunction -> PublicKey -> Signature -> ByteString -> Bool
verify hash pk (r,s) m
    -- Reject the signature if either 0 < r < q or 0 < s < q is not satisfied.
    | r <= 0 || r >= q || s <= 0 || s >= q = False
    | otherwise                            = v == r
    where
        (p,g,q) = public_params pk
        y       = public_y pk
        hm      = os2ip $ hash m

        w       = fromJust $ inverse s q
        u1      = (hm*w) `mod` q
        u2      = (r*w) `mod` q
        v       = ((expmod g u1 p) * (expmod y u2 p)) `mod` p `mod` q

expmod :: Integer -> Integer -> Integer -> Integer
expmod = exponantiation
