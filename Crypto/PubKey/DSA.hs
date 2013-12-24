-- |
-- Module      : Crypto.PubKey.DSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- An implementation of the Digital Signature Algorithm (DSA)

module Crypto.PubKey.DSA
    ( Params(..)
    , Signature(..)
    , PublicKey(..)
    , PrivateKey(..)
    -- * generation
    , generatePrivate
    , calculatePublic
    -- * signature primitive
    , sign
    , signWith
    -- * verification primitive
    , verify
    ) where

import Crypto.Random
import Data.Maybe
import Data.ByteString (ByteString)
import Crypto.Number.ModArithmetic (expFast, expSafe, inverse)
import Crypto.Number.Serialize
import Crypto.Number.Generate
import Crypto.Types.PubKey.DSA
import Crypto.PubKey.HashDescr

-- | generate a private number with no specific property
-- this number is usually called X in DSA text.
generatePrivate :: CPRG g => g -> Params -> (PrivateNumber, g)
generatePrivate rng (Params _ _ q) = generateMax rng q

-- | Calculate the public number from the parameters and the private key
calculatePublic :: Params -> PrivateNumber -> PublicNumber
calculatePublic (Params p g _) x = expSafe g x p

-- | sign message using the private key and an explicit k number.
signWith :: Integer         -- ^ k random number
         -> PrivateKey      -- ^ private key
         -> HashFunction    -- ^ hash function
         -> ByteString      -- ^ message to sign
         -> Maybe Signature
signWith k pk hash msg
    | r == 0 || s == 0  = Nothing
    | otherwise         = Just $ Signature r s
    where -- parameters
          (Params p g q) = private_params pk
          x         = private_x pk
          -- compute r,s
          kInv      = fromJust $ inverse k q
          hm        = os2ip $ hash msg
          r         = expSafe g k p `mod` q
          s         = (kInv * (hm + x * r)) `mod` q

-- | sign message using the private key.
sign :: CPRG g => g -> PrivateKey -> HashFunction -> ByteString -> (Signature, g)
sign rng pk hash msg =
    case signWith k pk hash msg of
        Nothing  -> sign rng' pk hash msg
        Just sig -> (sig, rng')
    where (Params _ _ q) = private_params pk
          (k, rng') = generateMax rng q

-- | verify a bytestring using the public key.
verify :: HashFunction -> PublicKey -> Signature -> ByteString -> Bool
verify hash pk (Signature r s) m
    -- Reject the signature if either 0 < r < q or 0 < s < q is not satisfied.
    | r <= 0 || r >= q || s <= 0 || s >= q = False
    | otherwise                            = v == r
    where (Params p g q) = public_params pk
          y       = public_y pk
          hm      = os2ip $ hash m

          w       = fromJust $ inverse s q
          u1      = (hm*w) `mod` q
          u2      = (r*w) `mod` q
          v       = ((expFast g u1 p) * (expFast y u2 p)) `mod` p `mod` q
