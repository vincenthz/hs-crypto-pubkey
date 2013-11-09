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
    , generatePublic
    , getShared
    ) where

import Crypto.Number.ModArithmetic (expSafe)
import Crypto.Number.Prime (generateSafePrime)
import Crypto.Number.Generate (generateOfSize)
import Crypto.Types.PubKey.DH
import Crypto.Random.API
import Control.Arrow (first)

-- | generate params from a specific generator (2 or 5 are common values)
-- we generate a safe prime (a prime number of the form 2p+1 where p is also prime)
generateParams :: CPRG g => g -> Int -> Integer -> (Params, g)
generateParams rng bits generator =
    first (\p -> Params p generator) $ generateSafePrime rng bits

-- | generate a private number with no specific property
-- this number is usually called X in DH text.
generatePrivate :: CPRG g => g -> Int -> (PrivateNumber, g)
generatePrivate rng bits = first PrivateNumber $ generateOfSize rng bits

-- | generate a public number that is for the other party benefits.
-- this number is usually called Y in DH text.
generatePublic :: Params -> PrivateNumber -> PublicNumber
generatePublic (Params p g) (PrivateNumber x) = PublicNumber $ expSafe g x p

-- | generate a shared key using our private number and the other party public number
getShared :: Params -> PrivateNumber -> PublicNumber -> SharedKey
getShared (Params p _) (PrivateNumber x) (PublicNumber y) = SharedKey $ expSafe y x p
