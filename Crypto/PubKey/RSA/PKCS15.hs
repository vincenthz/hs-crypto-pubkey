-- |
-- Module      : Crypto.PubKey.RSA.PKCS15
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE FlexibleInstances, CPP #-}
module Crypto.PubKey.RSA.PKCS15
    ( HashF
    , HashASN1
    , decrypt
    , decryptWithBlinding
    , encrypt
    , sign
    , verify
    ) where

import Control.Arrow (first)
import Crypto.Random
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

padPKCS1 :: CryptoRandomGen g => g -> Int -> ByteString -> Either Error (ByteString, g)
padPKCS1 rng len m = do
    (padding, rng') <- getRandomBytes rng (len - B.length m - 3)
    return (B.concat [ B.singleton 0, B.singleton 2, padding, B.singleton 0, m ], rng')
    where {- get random non-null bytes -}
          getRandomBytes :: CryptoRandomGen g => g -> Int -> Either Error (ByteString, g)
          getRandomBytes g n = do
                gend <- either (Left . RandomGenFailure) Right $ genBytes n g
                let (bytes, g') = first (B.pack . filter (/= 0) . B.unpack) gend
                let left          = (n - B.length bytes)
                if left == 0
                    then return (bytes, g')
                    else getRandomBytes g' left >>= return . first (B.append bytes)

unpadPKCS1 :: ByteString -> Either Error ByteString
unpadPKCS1 packed
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
    | otherwise                       = dp r pk c >>= unpadPKCS1
        where dp = if private_p pk /= 0 && private_q pk /= 0 then dpFast else dpSlow

{-| decrypt message using the private key.
 -  Use this method only when the decryption is not in a context where an attacker
 -  could gain information from the timing of the operation. In this context use
 -  decryptWithBlinding.
 -}
decrypt :: PrivateKey -- ^ RSA private key
        -> ByteString -- ^ cipher text
        -> Either Error ByteString
decrypt = decryptWithBlinding 1

{- | encrypt a bytestring using the public key and a CryptoRandomGen random generator.
 - the message need to be smaller than the key size - 11
 -}
encrypt :: CryptoRandomGen g => g -> PublicKey -> ByteString -> Either Error (ByteString, g)
encrypt rng pk m
    | B.length m > public_size pk - 11 = Left MessageTooLong
    | otherwise                        = do
        (em, rng') <- padPKCS1 rng (public_size pk) m
        c          <- ep pk em
        return (c, rng')

{-| sign message using private key, a hash and its ASN1 description -}
sign :: HashF -> HashASN1 -> PrivateKey -> ByteString -> Either Error ByteString
sign hash hashdesc pk m = makeSignature hash hashdesc (private_size pk) m >>= d 1 pk
    where d = if private_p pk /= 0 && private_q pk /= 0 then dpFast else dpSlow

{-| verify message with the signed message -}
verify :: HashF -> HashASN1 -> PublicKey -> ByteString -> ByteString -> Either Error Bool
verify hash hashdesc pk m sm = do
    s  <- makeSignature hash hashdesc (public_size pk) m
    em <- ep pk sm
    Right (s == em)

{- makeSignature for sign and verify -}
makeSignature :: HashF -> HashASN1 -> Int -> ByteString -> Either Error ByteString
makeSignature hash descr klen m
    | klen < siglen+1 = Left SignatureTooLong
    | otherwise       = Right $ B.concat [B.singleton 0,B.singleton 1,padding,B.singleton 0,signature]
    where
        signature = descr `B.append` hash m
        siglen    = B.length signature
        padding   = B.replicate (klen - siglen - 3) 0xff
