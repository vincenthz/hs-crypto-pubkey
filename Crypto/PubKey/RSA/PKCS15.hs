-- |
-- Module      : Crypto.PubKey.RSA.PKCS15
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE FlexibleInstances, CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.RSA.PKCS15
    (
    -- * signature types
      HashF
    , HashASN1
    -- * padding and unpadding
    , pad
    , padSignature
    , unpad
    -- * private key operations
    , decrypt
    , decryptSafer
    , decryptWithBlinding
    , sign
    , signSafer
    , signWithBlinding
    -- * public key operations
    , encrypt
    , verify
    ) where

import Crypto.Random.API
import Crypto.Number.Generate (generateMax)
import Crypto.Types.PubKey.RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types

type HashF = ByteString -> ByteString
type HashASN1 = ByteString

#if ! (MIN_VERSION_base(4,3,0))
instance Monad (Either Error) where
    return          = Right
    (Left x) >>= _  = Left x
    (Right x) >>= f = f x
#endif

-- | This produce a standard PKCS1.5 padding
pad :: CPRG g => g -> Int -> ByteString -> Either Error (ByteString, g)
pad rng len m
    | B.length m > len - 11 = Left MessageTooLong
    | otherwise             =
        let (padding, rng') = getNonNullRandom rng (len - B.length m - 3)
         in Right (B.concat [ B.singleton 0, B.singleton 2, padding, B.singleton 0, m ], rng')

        where {- get random non-null bytes -}
              getNonNullRandom :: CPRG g => g -> Int -> (ByteString, g)
              getNonNullRandom g n =
                    let (bs0,g') = genRandomBytes g n
                        bytes    = B.pack $ filter (/= 0) $ B.unpack $ bs0
                        left     = (n - B.length bytes)
                     in if left == 0
                        then (bytes, g')
                        else let (bend, g'') = getNonNullRandom g' left
                              in (bytes `B.append` bend, g'')

padSignature :: Int -> ByteString -> Either Error ByteString
padSignature klen signature
    | klen < siglen+1 = Left SignatureTooLong
    | otherwise       = Right $ B.concat [B.singleton 0,B.singleton 1,padding,B.singleton 0,signature]
    where
        siglen    = B.length signature
        padding   = B.replicate (klen - siglen - 3) 0xff

unpad :: ByteString -> Either Error ByteString
unpad packed
    | signal_error = Left MessageNotRecognized
    | otherwise    = Right m
    where
        (zt, ps0m)   = B.splitAt 2 packed
        (ps, zm)     = B.span (/= 0) ps0m
        (z, m)       = B.splitAt 1 zm
        signal_error = (B.unpack zt /= [0, 2]) || (B.unpack z /= [0]) || (B.length ps < 8)

{-| decrypt message using the private key using cryptoblinding technique.
 -  the r parameter need to be a randomly generated integer between 1 and N.
 -}
decryptWithBlinding :: Integer    -- ^ Random integer between 1 and N used for blinding
                    -> PrivateKey -- ^ RSA private key
                    -> ByteString -- ^ cipher text
                    -> Either Error ByteString
decryptWithBlinding r pk c
    | B.length c /= (private_size pk) = Left MessageSizeIncorrect
    | otherwise                       = unpad $ dpWithBlinding r pk c

{-| decrypt message using the private key.
 -  Use this method only when the decryption is not in a context where an attacker
 -  could gain information from the timing of the operation. In this context use
 -  decryptWithBlinding or decryptRandomTiming.
 -}
decrypt :: PrivateKey -- ^ RSA private key
        -> ByteString -- ^ cipher text
        -> Either Error ByteString
decrypt = decryptWithBlinding 1

-- | decrypt message using the private key and by generating a blinder.
--
-- try harder in hiding timing of the decryption operation with uses the
-- secret part of the key.
decryptSafer :: CPRG g
             => g          -- ^ random generator
             -> PrivateKey -- ^ RSA private key
             -> ByteString -- ^ cipher text
             -> (Either Error ByteString, g)
decryptSafer rng pk b =
    let (blinder, rng') = generateMax rng $ (private_n pk - 2) + 2
     in (decryptWithBlinding blinder pk b, rng')

{- | encrypt a bytestring using the public key and a CPRG random generator.
 - the message need to be smaller than the key size - 11
 -}
encrypt :: CPRG g => g -> PublicKey -> ByteString -> Either Error (ByteString, g)
encrypt rng pk m = do
    (em, rng') <- pad rng (public_size pk) m
    return (ep pk em, rng')

signWithBlinding :: Integer -> HashF -> HashASN1 -> PrivateKey -> ByteString -> Either Error ByteString
signWithBlinding blinder hash hashdesc pk m = dpWithBlinding blinder pk `fmap` makeSignature hash hashdesc (private_size pk) m

{-| sign message using private key, a hash and its ASN1 description -}
sign :: HashF -> HashASN1 -> PrivateKey -> ByteString -> Either Error ByteString
sign hash hashdesc pk m = dp pk `fmap` makeSignature hash hashdesc (private_size pk) m

-- | like sign, except it generates a blinder to obfuscate timings
signSafer :: CPRG g => g -> HashF -> HashASN1 -> PrivateKey -> ByteString -> (Either Error ByteString, g)
signSafer rng hash hashdesc pk m = do
    let (blinder, rng') = generateMax rng $ (private_n pk - 2) + 2
    (signWithBlinding blinder hash hashdesc pk m, rng')

{-| verify message with the signed message -}
verify :: HashF -> HashASN1 -> PublicKey -> ByteString -> ByteString -> Bool
verify hash hashdesc pk m sm =
    case makeSignature hash hashdesc (public_size pk) m of
        Left _  -> False
        Right s -> s == (ep pk sm)

{- makeSignature for sign and verify -}
makeSignature :: HashF -> HashASN1 -> Int -> ByteString -> Either Error ByteString
makeSignature hash descr klen m = padSignature klen signature
    where signature = descr `B.append` hash m
