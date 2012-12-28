module Crypto.PubKey.RSA.OAEP
    (
      OAEPParams(..)
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
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- | Parameters for OAEP encryption/decryption
data OAEPParams = OAEPParams
    { oaepHash       :: HashFunction     -- ^ Hash function to use.
    , oaepMaskGenAlg :: MaskGenAlgorithm -- ^ Mask Gen algorithm to use.
    , oaepLabel      :: Maybe ByteString -- ^ Optional label prepended to message.
    }

-- | Default Params with a specified hash function
defaultOAEPParams :: HashFunction -> PSSParams
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
        -> Either Error (ByteString, g)
encrypt g oaep pk msg
    | mLen > k – 2 * hashLen – 2 = Left MessageTooLong
    | otherwise                  = ep pk em
    where k          = public_size pk
          mLen       = B.length msg
          hashF      = oaepHash oaep
          labelHash  = hashF $ maybe B.empty oaepLabel oaep
          hashLen    = B.length lHash
          ps         = B.replicate (k – mLen – 2 * hashLen – 2) 0
          db         = B.concat [labelHash, ps, B.singleton 0x1, msg]
          (seed, g') = genRandomBytes g hashLen
          dbmask     = (oaepMaskGenAlg params) hashF seed (k - hashLen - 1)
          maskedDB   = B.pack $ B.zipWith xor db dbmask
          seedMask   = (oaepMaskGenAlg params) hashF maskedDB hashLen
          maskedSeed = B.pack $ B.zipWith xor seed seedMask
          em         = B.concat [B.singleton 0x0,maskedSeed,maskedDB]

-- | Decrypt a ciphertext using OAEP
decrypt :: OAEPParams -- ^ OAEP params to use for decryption.
        -> PrivateKey -- ^ Private key
        -> ByteString -- ^ Cipher text
        -> Either Error ByteString
decrypt oaep pk cipher
    | B.length cipher /= (private_size pk) = Left MessageSizeIncorrect
    | otherwise                            = undefined
