-- | Elliptic Curve Arithmetic.
--
-- /WARNING:/ These functions are vulnerable to timing attacks.
module Crypto.PubKey.ECC.Prim
    ( pointAdd
    , pointDouble
    , pointMul
    , isPointAtInfinity
    ) where

import Data.Maybe
import Crypto.Number.ModArithmetic
import Crypto.Number.F2m
import Crypto.Types.PubKey.ECC

--TODO: Extract helper function for `fromMaybe PointO...`

-- | Elliptic Curve point addition.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAdd :: Curve -> Point -> Point -> Point
pointAdd _ PointO PointO = PointO
pointAdd _ PointO q = q
pointAdd _ p PointO = p
pointAdd c@(CurveFP (CurvePrime pr _)) p@(Point xp yp) q@(Point xq yq)
    | p == Point xq (-yq) = PointO
    | p == q = pointDouble c p
    | otherwise = fromMaybe PointO $ do
                      s <- divmod (yp - yq) (xp - xq) pr
                      let xr = (s ^ (2::Int) - xp - xq) `mod` pr
                          yr = (s * (xp - xr) - yp) `mod` pr
                      return $ Point xr yr
pointAdd c@(CurveF2m (CurveBinary fx cc)) p@(Point xp yp) q@(Point xq yq)
    | p == Point xq (xq `addF2m` yq) = PointO
    | p == q = pointDouble c p
    | otherwise = fromMaybe PointO $ do
                     s <- divF2m fx (yp `addF2m` yq) (xp `addF2m` xq)
                     let xr = mulF2m fx s s `addF2m` s `addF2m` xp `addF2m` xq `addF2m` a
                         yr = mulF2m fx s (xp `addF2m` xr) `addF2m` xr `addF2m` yp
                     return $ Point xr yr
  where a = ecc_a cc

-- | Elliptic Curve point doubling.
--
-- /WARNING:/ Vulnerable to timing attacks.
--
-- This perform the following calculation:
-- > lambda = (3 * xp ^ 2 + a) / 2 yp
-- > xr = lambda ^ 2 - 2 xp
-- > yr = lambda (xp - xr) - yp
--
-- With binary curve:
-- > xp == 0   => P = O
-- > otherwise =>
-- >    s = xp + (yp / xp)
-- >    xr = s ^ 2 + s + a
-- >    yr = xp ^ 2 + (s+1) * xr
--
pointDouble :: Curve -> Point -> Point
pointDouble _ PointO = PointO
pointDouble (CurveFP (CurvePrime pr cc)) (Point xp yp) = fromMaybe PointO $ do
    lambda <- divmod (3 * xp ^ (2::Int) + a) (2 * yp) pr
    let xr = (lambda ^ (2::Int) - 2 * xp) `mod` pr
        yr = (lambda * (xp - xr) - yp) `mod` pr
    return $ Point xr yr
  where a = ecc_a cc
pointDouble (CurveF2m (CurveBinary fx cc)) (Point xp yp)
    | xp == 0   = PointO
    | otherwise = fromMaybe PointO $ do
        s <- return . addF2m xp =<< divF2m fx yp xp
        let xr = mulF2m fx s s `addF2m` s `addF2m` a
            yr = mulF2m fx xp xp `addF2m` mulF2m fx xr (s `addF2m` 1)
        return $ Point xr yr
  where a = ecc_a cc

-- | Elliptic curve point multiplication (double and add algorithm).
--
-- /WARNING:/ Vulnerable to timing attacks.
pointMul :: Curve -> Integer -> Point -> Point
pointMul _ _ PointO = PointO
pointMul c n p@(Point xp yp)
    | n <  0 = pointMul c (-n) (Point xp (-yp))
    | n == 0 = PointO
    | n == 1 = p
    | odd n = pointAdd c p (pointMul c (n - 1) p)
    | otherwise = pointMul c (n `div` 2) (pointDouble c p)

-- | Check if a point is the point at infinity.
isPointAtInfinity :: Point -> Bool
isPointAtInfinity PointO = True
isPointAtInfinity _      = False

-- | div and mod
divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod y x m = do
    i <- inverse (x `mod` m) m
    return $ y * i `mod` m
