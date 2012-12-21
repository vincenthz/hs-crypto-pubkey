-- |
-- Module      : Crypto.PubKey.RSA.PKCS15
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.RSA.PKCS15
    (
    -- * padding and unpadding
      pad
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
import Crypto.PubKey.HashDescr

-- | This produce a standard PKCS1.5 padding for encryption
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

-- | Produce a standard PKCS1.5 padding for signature
padSignature :: Int -> ByteString -> Either Error ByteString
padSignature klen signature
    | klen < siglen+1 = Left SignatureTooLong
    | otherwise       = Right $ B.concat [B.singleton 0,B.singleton 1,padding,B.singleton 0,signature]
    where
        siglen    = B.length signature
        padding   = B.replicate (klen - siglen - 3) 0xff

-- | Try to remove a standard PKCS1.5 encryption padding.
unpad :: ByteString -> Either Error ByteString
unpad packed
    | signal_error = Left MessageNotRecognized
    | otherwise    = Right m
    where
        (zt, ps0m)   = B.splitAt 2 packed
        (ps, zm)     = B.span (/= 0) ps0m
        (z, m)       = B.splitAt 1 zm
        signal_error = zt /= "\x00\x02" || z /= "\x00" || (B.length ps < 8)

-- | decrypt message using the private key using cryptoblinding technique.
--
-- the r parameter need to be a randomly generated integer between 1 and N.
decryptWithBlinding :: Integer    -- ^ Random integer between 1 and N used for blinding
                    -> PrivateKey -- ^ RSA private key
                    -> ByteString -- ^ cipher text
                    -> Either Error ByteString
decryptWithBlinding r pk c
    | B.length c /= (private_size pk) = Left MessageSizeIncorrect
    | otherwise                       = unpad $ dpWithBlinding r pk c

-- | decrypt message using the private key.
-- Use this method only when the decryption is not in a context where an attacker
-- could gain information from the timing of the operation. In this context use
-- decryptWithBlinding or decryptSafer.
--
decrypt :: PrivateKey -- ^ RSA private key
        -> ByteString -- ^ cipher text
        -> Either Error ByteString
decrypt pk c
    | B.length c /= (private_size pk) = Left MessageSizeIncorrect
    | otherwise                       = unpad $ dp pk c

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

-- | encrypt a bytestring using the public key and a CPRG random generator.
--
-- the message need to be smaller than the key size - 11
encrypt :: CPRG g => g -> PublicKey -> ByteString -> Either Error (ByteString, g)
encrypt rng pk m = do
    (em, rng') <- pad rng (public_size pk) m
    return (ep pk em, rng')

-- | just like sign but use an explicit blinding to obfuscate timings
signWithBlinding :: Integer -> HashDescr -> PrivateKey -> ByteString -> Either Error ByteString
signWithBlinding blinder hashDescr pk m = dpWithBlinding blinder pk `fmap` makeSignature hashDescr (private_size pk) m

-- | sign message using private key, a hash and its ASN1 description
sign :: HashDescr -> PrivateKey -> ByteString -> Either Error ByteString
sign hashDescr pk m = dp pk `fmap` makeSignature hashDescr (private_size pk) m

-- | like sign, except it generates a blinder to obfuscate timings
signSafer :: CPRG g => g -> HashDescr -> PrivateKey -> ByteString -> (Either Error ByteString, g)
signSafer rng hashDescr pk m =
    let (blinder, rng') = generateMax rng $ (private_n pk - 2) + 2
     in (signWithBlinding blinder hashDescr pk m, rng')

-- | verify message with the signed message
verify :: HashDescr -> PublicKey -> ByteString -> ByteString -> Bool
verify hashDescr pk m sm =
    case makeSignature hashDescr (public_size pk) m of
        Left _  -> False
        Right s -> s == (ep pk sm)

{- makeSignature for sign and verify -}
makeSignature :: HashDescr -> Int -> ByteString -> Either Error ByteString
makeSignature hashDescr klen m = padSignature klen signature
    where signature = (digestToASN1 hashDescr) $ (hashFunction hashDescr) m
