{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.RSA.OAEP
    (
      OAEPParams(..)
    , defaultOAEPParams
    -- * OAEP encryption
    , encryptWithSeed
    , encrypt
    -- * OAEP decryption
    , decrypt
    , decryptSafer
    , decryptWithBlinding
    ) where

import Crypto.Random.API
import Crypto.Types.PubKey.RSA
import Crypto.PubKey.HashDescr
import Crypto.PubKey.MaskGenFunction
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types
import Crypto.PubKey.RSA (generateBlinder)
import Crypto.PubKey.Internal (and')
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bits (xor)

-- | Parameters for OAEP encryption/decryption
data OAEPParams = OAEPParams
    { oaepHash       :: HashFunction     -- ^ Hash function to use.
    , oaepMaskGenAlg :: MaskGenAlgorithm -- ^ Mask Gen algorithm to use.
    , oaepLabel      :: Maybe ByteString -- ^ Optional label prepended to message.
    }

-- | Default Params with a specified hash function
defaultOAEPParams :: HashFunction -> OAEPParams
defaultOAEPParams hashF =
    OAEPParams { oaepHash         = hashF
               , oaepMaskGenAlg   = mgf1
               , oaepLabel        = Nothing
               }

encryptWithSeed :: ByteString
                -> OAEPParams
                -> PublicKey
                -> ByteString
                -> Either Error ByteString
encryptWithSeed seed oaep pk msg
    | k < 2*hashLen+2          = Left InvalidParameters
    | B.length seed /= hashLen = Left InvalidParameters
    | mLen > k - 2*hashLen-2   = Left MessageTooLong
    | otherwise                = Right $ ep pk em
    where -- parameters
          k          = public_size pk
          mLen       = B.length msg
          hashF      = oaepHash oaep
          mgf        = (oaepMaskGenAlg oaep) hashF
          labelHash  = hashF $ maybe B.empty id $ oaepLabel oaep
          hashLen    = B.length labelHash

          -- put fields
          ps         = B.replicate (k - mLen - 2*hashLen - 2) 0
          db         = B.concat [labelHash, ps, B.singleton 0x1, msg]
          dbmask     = mgf seed (k - hashLen - 1)
          maskedDB   = B.pack $ B.zipWith xor db dbmask
          seedMask   = mgf maskedDB hashLen
          maskedSeed = B.pack $ B.zipWith xor seed seedMask
          em         = B.concat [B.singleton 0x0,maskedSeed,maskedDB]

-- | Encrypt a message using OAEP
encrypt :: CPRG g
        => g          -- ^ random number generator.
        -> OAEPParams -- ^ OAEP params to use for encryption.
        -> PublicKey  -- ^ Public key.
        -> ByteString -- ^ Message to encrypt
        -> (Either Error ByteString, g)
encrypt g oaep pk msg = (encryptWithSeed seed oaep pk msg, g')
    where hashF      = oaepHash oaep
          hashLen    = B.length (hashF B.empty)
          (seed, g') = genRandomBytes g hashLen

-- | un-pad a OAEP encoded message.
--
-- It doesn't apply the RSA decryption primitive
unpad :: OAEPParams  -- ^ OAEP params to use
      -> Int         -- ^ size of the key in bytes
      -> ByteString  -- ^ encoded message (not encrypted)
      -> Either Error ByteString
unpad oaep k em
    | paddingSuccess = Right msg
    | otherwise      = Left MessageNotRecognized
    where -- parameters
          hashF      = oaepHash oaep
          mgf        = (oaepMaskGenAlg oaep) hashF
          labelHash  = hashF $ maybe B.empty id $ oaepLabel oaep
          hashLen    = B.length labelHash
          -- getting em's fields
          (pb, em0)  = B.splitAt 1 em
          (maskedSeed,maskedDB) = B.splitAt hashLen em0
          seedMask   = mgf maskedDB hashLen
          seed       = B.pack $ B.zipWith xor maskedSeed seedMask
          dbmask     = mgf seed (k - hashLen - 1)
          db         = B.pack $ B.zipWith xor maskedDB dbmask
          -- getting db's fields
          (labelHash',db1) = B.splitAt hashLen db
          (_,db2)    = B.break (/= 0) db1
          (ps1,msg)  = B.splitAt 1 db2

          paddingSuccess = and' [ labelHash' == labelHash -- no need for constant eq
                                , ps1        == "\x01"
                                , pb         == "\x00"
                                ]

-- | Decrypt a ciphertext using OAEP and a predefined blinder.
decryptWithBlinding :: Blinder    -- ^ Blinder to use
                    -> OAEPParams -- ^ OAEP params to use for decryption.
                    -> PrivateKey -- ^ Private key
                    -> ByteString -- ^ Cipher text
                    -> Either Error ByteString
decryptWithBlinding blinder oaep pk cipher
    | B.length cipher /= k = Left MessageSizeIncorrect
    | k < 2*hashLen+2      = Left InvalidParameters
    | otherwise            = unpad oaep (private_size pk) $ dpWithBlinding blinder pk cipher
    where -- parameters
          k          = private_size pk
          hashF      = oaepHash oaep
          hashLen    = B.length (hashF B.empty)

-- | Decrypt a ciphertext using OAEP
--
-- Use this method only when the decryption is not in a context where an attacker
-- could gain information from the timing of the operation. In this context use
-- decryptWithBlinding or decryptSafer.
decrypt :: OAEPParams -- ^ OAEP params to use for decryption.
        -> PrivateKey -- ^ Private key
        -> ByteString -- ^ Cipher text
        -> Either Error ByteString
decrypt oaep pk cipher
    | B.length cipher /= k = Left MessageSizeIncorrect
    | k < 2*hashLen+2      = Left InvalidParameters
    | otherwise            = unpad oaep (private_size pk) $ dp pk cipher
    where -- parameters
          k          = private_size pk
          hashF      = oaepHash oaep
          hashLen    = B.length (hashF B.empty)

-- | Decrypt a ciphertext using OAEP and by generating a blinder.
--
-- try harder in hiding timing of the decryption operation with uses the
-- secret part of the key.
decryptSafer :: CPRG g
             => g          -- ^ random number generator
             -> OAEPParams -- ^ OAEP params to use for decryption
             -> PrivateKey -- ^ Private key
             -> ByteString -- ^ Cipher text
             -> (Either Error ByteString, g)
decryptSafer rng oaep pk cipher = (decryptWithBlinding blinder oaep pk cipher, rng')
    where (blinder, rng') = generateBlinder rng (private_n pk)
