module Crypto.PubKey.ECC.DH (
    Curve
  , PublicPoint
  , PrivateNumber
  , SharedKey(..)
  , generatePrivate
  , calculatePublic
  , getShared
  ) where

import Crypto.Number.Generate (generateMax)
import Crypto.PubKey.ECC.Prim (pointMul)
import Crypto.Random (CPRG)
import Crypto.Types.PubKey.DH (SharedKey(..))
import Crypto.Types.PubKey.ECC (PublicPoint, PrivateNumber, Curve, Point(..))
import Crypto.Types.PubKey.ECC (ecc_n, ecc_g, common_curve)

-- | Generating a private number d.
generatePrivate :: CPRG g => g -> Curve -> (PrivateNumber, g)
generatePrivate rng curve = generateMax rng n
  where
    n = ecc_n $ common_curve curve

-- | Generating a public point Q.
calculatePublic :: Curve -> PrivateNumber -> PublicPoint
calculatePublic curve d = q
  where
    g = ecc_g $ common_curve curve
    q = pointMul curve d g

-- | Generating a shared key using our private number and
--   the other party public point.
getShared :: Curve -> PrivateNumber -> PublicPoint -> SharedKey
getShared curve db qa = SharedKey x
  where
    Point x _ = pointMul curve db qa
