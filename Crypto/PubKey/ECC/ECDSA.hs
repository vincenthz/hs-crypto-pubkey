-- | /WARNING:/ Signature operations may leak the private key. Signature verification
-- should be safe.
module Crypto.PubKey.ECC.ECDSA
    ( module Crypto.Types.PubKey.ECDSA
    , signWith
    , sign
    , verify
    ) where

import Control.Monad
import Crypto.Random.API
import Data.Bits (shiftR)
import Data.ByteString (ByteString)
import Crypto.Number.ModArithmetic (inverse)
import Crypto.Number.Serialize
import Crypto.Number.Generate
import Crypto.Types.PubKey.ECDSA
import Crypto.Types.PubKey.ECC
import Crypto.PubKey.HashDescr
import Crypto.PubKey.ECC.Prim

-- | Sign message using the private key and an explicit k number.
--
-- /WARNING:/ Vulnerable to timing attacks.
signWith :: Integer         -- ^ k random number
         -> PrivateKey      -- ^ private key
         -> HashFunction    -- ^ hash function
         -> ByteString      -- ^ message to sign
         -> Maybe Signature
signWith k (PrivateKey curve d) hash msg = do
    let z = tHash hash msg n
        CurveCommon _ _ g n _ = common_curve curve
    let point = pointMul curve k g
    r <- case point of
              PointO    -> Nothing
              Point x _ -> return $ x `mod` n
    kInv <- inverse k n
    let s = kInv * (z + r * d) `mod` n
    when (r == 0 || s == 0) Nothing
    return $ Signature r s

-- | Sign message using the private key.
--
-- /WARNING:/ Vulnerable to timing attacks.
sign :: CPRG g => g -> PrivateKey -> HashFunction -> ByteString -> (Signature, g)
sign rng pk hash msg =
    case signWith k pk hash msg of
         Nothing  -> sign rng' pk hash msg
         Just sig -> (sig, rng')
  where n = ecc_n . common_curve $ private_curve pk
        (k, rng') = generateBetween rng 1 (n - 1)

-- | Verify a bytestring using the public key.
verify :: HashFunction -> PublicKey -> Signature -> ByteString -> Bool
verify _ (PublicKey _ PointO) _ _ = False
verify hash pk@(PublicKey curve q) (Signature r s) msg
    | r < 1 || r >= n || s < 1 || s >= n = False
    | otherwise = maybe False (r ==) $ do
        w <- inverse s n
        let z  = tHash hash msg n
            u1 = z * w `mod` n
            u2 = r * w `mod` n
            -- TODO: Use Shamir's trick
            g' = pointMul curve u1 g
            q' = pointMul curve u2 q
            x  = pointAdd curve g' q'
        case x of
             PointO     -> Nothing
             Point x1 _ -> return $ x1 `mod` n
  where n = ecc_n cc
        g = ecc_g cc
        cc = common_curve $ public_curve pk

-- | Truncate and hash.
tHash ::  HashFunction -> ByteString -> Integer -> Integer
tHash hash m n
    | d > 0 = shiftR e d
    | otherwise = e
  where e = os2ip $ hash m
        d = log2 e - log2 n
        log2 = ceiling . logBase (2 :: Double) . fromIntegral
