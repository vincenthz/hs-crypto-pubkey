{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.PubKey.DH
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.PubKey.DH
    ( Params(..)
    , PublicNumber
    , PrivateNumber
    , SharedKey
    , generateParams
    , generatePrivate
    , calculatePublic
    , generatePublic
    , getShared
    ) where

import Crypto.Number.ModArithmetic (expSafe)
import Crypto.Number.Prime (generateSafePrime)
import Crypto.Number.Generate (generateMax)
import Crypto.Types.PubKey.DH
import Crypto.Random
import Control.Arrow (first)

-- | generate params from a specific generator (2 or 5 are common values)
-- we generate a safe prime (a prime number of the form 2p+1 where p is also prime)
generateParams :: CPRG g => g -> Int -> Integer -> (Params, g)
generateParams rng bits generator =
    first (\p -> Params p generator) $ generateSafePrime rng bits

-- | generate a private number with no specific property
-- this number is usually called X in DH text.
generatePrivate :: CPRG g => g -> Params -> (PrivateNumber, g)
generatePrivate rng (Params p _) = first PrivateNumber $ generateMax rng p

-- | calculate the public number from the parameters and the private key
-- this number is usually called Y in DH text.
calculatePublic :: Params -> PrivateNumber -> PublicNumber
calculatePublic (Params p g) (PrivateNumber x) = PublicNumber $ expSafe g x p

-- | calculate the public number from the parameters and the private key
-- this number is usually called Y in DH text.
--
-- DEPRECATED use calculatePublic
generatePublic :: Params -> PrivateNumber -> PublicNumber
generatePublic = calculatePublic
-- commented until 0.3 {-# DEPRECATED generatePublic "use calculatePublic" #-}

-- | generate a shared key using our private number and the other party public number
getShared :: Params -> PrivateNumber -> PublicNumber -> SharedKey
getShared (Params p _) (PrivateNumber x) (PublicNumber y) = SharedKey $ expSafe y x p
