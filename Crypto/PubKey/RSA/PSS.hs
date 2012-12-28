module Crypto.PubKey.RSA.PSS
    ( PSSParams(..)
    , defaultPSSParams
    , defaultPSSParamsSHA1
    -- * Sign and verify functions
    , signWithSalt
    , sign
    , verify
    ) where

import Crypto.Random.API
import Crypto.Types.PubKey.RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types
import Crypto.PubKey.HashDescr
import Crypto.PubKey.MaskGenFunction
import Crypto.Hash
import Data.Bits (xor)
import Data.Word

-- | Parameters for PSS signature/verification.
data PSSParams = PSSParams { pssHash         :: HashFunction     -- ^ Hash function to use
                           , pssMaskGenAlg   :: MaskGenAlgorithm -- ^ Mask Gen algorithm to use
                           , pssSaltLength   :: Int              -- ^ Length of salt. need to be <= to hLen.
                           , pssTrailerField :: Word8            -- ^ Trailer field, usually 0xbc
                           }

-- | Default Params with a specified hash function
defaultPSSParams :: HashFunction -> PSSParams
defaultPSSParams hashF =
    PSSParams { pssHash         = hashF
              , pssMaskGenAlg   = mgf1
              , pssSaltLength   = B.length $ hashF B.empty
              , pssTrailerField = 0xbc
              }

-- | Default Params using SHA1 algorithm.
defaultPSSParamsSHA1 :: PSSParams
defaultPSSParamsSHA1 = defaultPSSParams (digestToByteString . (hash :: ByteString -> Digest SHA1))

-- | Sign using the PSS parameters and the salt explicitely passed as parameters.
--
-- the function ignore SaltLength from the PSS Parameters
signWithSalt :: PSSParams  -- ^ PSS Parameters to use
             -> ByteString -- ^ Salt to use
             -> PrivateKey -- ^ RSA Private Key
             -> ByteString -- ^ Message to sign
             -> Either Error ByteString
signWithSalt params salt pk m
    -- | hashLen          = Left SignatureTooLong
    | otherwise        = Right $ dp pk em
    where mHash    = (pssHash params) m
          dbLen    = private_size pk - hashLen - 1
          saltLen  = B.length salt
          hashLen  = B.length (hashF B.empty)
          hashF    = pssHash params

          m'       = B.concat [B.replicate 8 0,mHash,salt]
          h        = hashF m'
          db       = B.concat [B.replicate (dbLen - saltLen - 1) 0,B.singleton 1,salt]
          dbmask   = (pssMaskGenAlg params) hashF h dbLen
          maskedDB = B.pack $ B.zipWith xor db dbmask
          em       = B.concat [maskedDB, h, B.singleton (pssTrailerField params)]

-- | Sign using the PSS Parameters
sign :: CPRG g
     => g               -- ^ random generator to use to generate the salt
     -> PSSParams       -- ^ PSS Parameters to use
     -> PrivateKey      -- ^ RSA Private Key
     -> ByteString      -- ^ Message to sign
     -> (Either Error ByteString, g)
sign rng params pk m = (signWithSalt params salt pk m, rng')
    where
          (salt,rng') = genRandomBytes rng (pssSaltLength params)

-- | Verify a signature using the PSS Parameters
verify :: PSSParams  -- ^ PSS Parameters to use to verify,
                     --   this need to be identical to the parameters when signing
       -> PublicKey  -- ^ RSA Public Key
       -> ByteString -- ^ Message to verify
       -> ByteString -- ^ Signature
       -> Bool
verify params pk m s
    | public_size pk /= B.length s        = False
    | B.last em /= pssTrailerField params = False
    | not (B.all (== 0) ps0)              = False
    | b1 /= B.singleton 1                 = False
    | otherwise                           = h == h'
        where em        = ep pk s
              maskedDB  = B.take (B.length em - hashLen - 1) em
              h         = B.take hashLen $ B.drop (B.length maskedDB) em
              dbLen     = public_size pk - hashLen - 1
              dbmask    = (pssMaskGenAlg params) hashF h dbLen
              db        = B.pack $ B.zipWith xor maskedDB dbmask
              (ps0,z)   = B.break (== 1) db
              (b1,salt) = B.splitAt 1 z
              mHash     = hashF m
              m'        = B.concat [B.replicate 8 0,mHash,salt]
              h'        = hashF m'
              hashF     = pssHash params
              hashLen   = B.length (hashF B.empty)
