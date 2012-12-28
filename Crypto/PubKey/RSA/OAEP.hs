{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.RSA.OAEP
    (
      OAEPParams(..)
    , defaultOAEPParams
    -- * OAEP encryption and decryption primitives
    , encrypt
    , decrypt
    ) where

import Crypto.Random.API
import Crypto.Types.PubKey.RSA
import Crypto.PubKey.HashDescr
import Crypto.PubKey.MaskGenFunction
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types
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

-- | Encrypt a message using OAEP
encrypt :: CPRG g
        => g          -- ^ random number generator.
        -> OAEPParams -- ^ OAEP params to use for encryption.
        -> PublicKey  -- ^ Public key.
        -> ByteString -- ^ Message to encrypt
        -> (Either Error ByteString, g)
encrypt g oaep pk msg
    | k < 2*hashLen+2              = (Left InvalidParameters, g)
    | mLen > k - 2*hashLen-2       = (Left MessageTooLong, g)
    | otherwise                    = (Right (ep pk em), g')
    where -- parameters
          k          = public_size pk
          mLen       = B.length msg
          hashF      = oaepHash oaep
          mgf        = (oaepMaskGenAlg oaep) hashF
          labelHash  = hashF $ maybe B.empty id $ oaepLabel oaep
          hashLen    = B.length labelHash
          (seed, g') = genRandomBytes g hashLen

          -- put fields
          ps         = B.replicate (k - mLen - 2*hashLen - 2) 0
          db         = B.concat [labelHash, ps, B.singleton 0x1, msg]
          dbmask     = mgf seed (k - hashLen - 1)
          maskedDB   = B.pack $ B.zipWith xor db dbmask
          seedMask   = mgf maskedDB hashLen
          maskedSeed = B.pack $ B.zipWith xor seed seedMask
          em         = B.concat [B.singleton 0x0,maskedSeed,maskedDB]

-- | Decrypt a ciphertext using OAEP
decrypt :: OAEPParams -- ^ OAEP params to use for decryption.
        -> PrivateKey -- ^ Private key
        -> ByteString -- ^ Cipher text
        -> Either Error ByteString
decrypt oaep pk cipher
    | B.length cipher /= k = Left MessageSizeIncorrect
    | k < 2*hashLen+2      = Left InvalidParameters
    | paddingSuccess       = Right msg
    | otherwise            = Left MessageNotRecognized
    where -- parameters
          k          = private_size pk
          hashF      = oaepHash oaep
          mgf        = (oaepMaskGenAlg oaep) hashF
          labelHash  = hashF $ maybe B.empty id $ oaepLabel oaep
          hashLen    = B.length labelHash
          -- getting em's fields
          em         = dp pk cipher
          (pb, em0)  = B.splitAt 1 em
          (maskedSeed,maskedDB) = B.splitAt hashLen em0
          seedMask   = mgf maskedDB hashLen
          seed       = B.pack $ B.zipWith xor maskedSeed seedMask
          dbmask     = mgf seed (k - hashLen - 1)
          db         = B.pack $ B.zipWith xor maskedDB dbmask
          -- getting db's fields
          (labelHash',db1) = B.splitAt hashLen db
          (_,db2)    = B.span (/= 0) db1
          (ps1,msg)  = B.splitAt 1 db2

          paddingSuccess = and' [ labelHash' == labelHash -- no need for constant eq
                                , ps1        == "\x01"
                                , pb         == "\x00"
                                ]
