-- | Elliptic Curve Arithmetic.
--
-- /WARNING:/ These functions are vulnerable to timing attacks.
{-# LANGUAGE BangPatterns #-}
module Crypto.PubKey.ECC.Prim
    ( pointAdd
    , pointDouble
    , pointMul
    , isPointAtInfinity
    ) where

import Data.Maybe
import Data.Bits
import Crypto.Number.ModArithmetic
import Crypto.Number.F2m
import Crypto.Types.PubKey.ECC

--TODO: Extract helper function for `fromMaybe PointO...`

-- | Elliptic Curve point addition.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAdd :: Curve -> Point -> Point -> Point
pointAdd (CurveFP (CurvePrime pr cc))   !p !q = pointAddPrime pr cc p q
pointAdd (CurveF2m (CurveBinary fx cc)) !p !q = pointAddBinary fx cc p q

pointAddPrime :: Integer -> CurveCommon -> Point -> Point -> Point
pointAddPrime _  _  PointO PointO = PointO
pointAddPrime _  _  PointO q      = q
pointAddPrime _  _  p      PointO = p
pointAddPrime pr cc p@(Point xp yp) q@(Point xq yq)
    | p == Point xq (-yq) = PointO
    | p == q              = pointDoublePrime pr cc p
    | otherwise           = fromMaybe PointO $ do
        !s <- divmod (yp - yq) (xp - xq) pr
        let !xr = (s ^ (2::Int) - xp - xq) `mod` pr
            !yr = (s * (xp - xr) - yp) `mod` pr
        return $! Point xr yr
{-# INLINE pointAddPrime #-}

pointAddBinary :: Integer -> CurveCommon -> Point -> Point -> Point
pointAddBinary _  _  PointO PointO = PointO
pointAddBinary _  _  PointO q      = q
pointAddBinary _  _  p      PointO = p
pointAddBinary fx cc p@(Point xp yp) q@(Point xq yq)
    | p == Point xq (xq `addF2m` yq) = PointO
    | p == q                         = pointDoubleBinary fx cc p
    | otherwise                      = fromMaybe PointO $ do
        !s <- divF2m fx (yp `addF2m` yq) (xp `addF2m` xq)
        let !xr = mulF2m fx s s `addF2m` s `addF2m` xp `addF2m` xq `addF2m` a
            !yr = mulF2m fx s (xp `addF2m` xr) `addF2m` xr `addF2m` yp
        return $! Point xr yr
  where a = ecc_a cc
{-# INLINE pointAddBinary #-}

-- | Elliptic Curve point doubling.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointDouble :: Curve -> Point -> Point
pointDouble (CurveFP (CurvePrime pr cc))   !p = pointDoublePrime pr cc p
pointDouble (CurveF2m (CurveBinary fx cc)) !p = pointDoubleBinary fx cc p

pointDoublePrime :: Integer -> CurveCommon -> Point -> Point
pointDoublePrime _  _  PointO        = PointO
pointDoublePrime pr cc (Point xp yp) = fromMaybe PointO $ do
    l <- divmod (3 * xp ^ (2::Int) + a) (2 * yp) pr
    let xr = (l ^ (2::Int) - 2 * xp) `mod` pr
        yr = (l * (xp - xr) - yp) `mod` pr
    return $ Point xr yr
  where a = ecc_a cc
{-# INLINE pointDoublePrime #-}

pointDoubleBinary :: Integer -> CurveCommon -> Point -> Point
pointDoubleBinary _  _  PointO        = PointO
pointDoubleBinary fx cc (Point xp yp) = fromMaybe PointO $ do
    s <- return . addF2m xp =<< divF2m fx yp xp
    let xr = mulF2m fx s s `addF2m` s `addF2m` a
        yr = mulF2m fx xp xp `addF2m` mulF2m fx xr (s `addF2m` 1)
    return $ Point xr yr
  where a = ecc_a cc
{-# INLINE pointDoubleBinary #-}

-- | Elliptic curve point multiplication (double and add algorithm).
--
-- /WARNING:/ Vulnerable to timing attacks.
pointMul :: Curve -> Integer -> Point -> Point
pointMul _ _ PointO = PointO
pointMul c n p@(Point xp yp)
    | n <  0    = pointMul c (-n) (Point xp (-yp))
    | n == 0    = PointO
    | otherwise = doubleAndAdd n p
  where doubleAndAdd = case c of
            CurveFP (CurvePrime pr cc)   -> doubleAndAddPrime pr cc
            CurveF2m (CurveBinary fx cc) -> doubleAndAddBinary fx cc

        doubleAndAddPrime pr cc = loop
          where loop i !z
                    | i == 1    = z
                    | odd i     = pointAddPrime pr cc z (loop (i `unsafeShiftR` 1) (pointDoublePrime pr cc z))
                    | otherwise = loop (i `unsafeShiftR` 1) (pointDoublePrime pr cc z)

        doubleAndAddBinary fx cc = loop
          where loop i !z
                    | i == 1    = z
                    | odd i     = pointAddBinary fx cc z (loop (i `unsafeShiftR` 1) (pointDoubleBinary fx cc z))
                    | otherwise = loop (i `unsafeShiftR` 1) (pointDoubleBinary fx cc z)

-- | Check if a point is the point at infinity.
isPointAtInfinity :: Point -> Bool
isPointAtInfinity PointO = True
isPointAtInfinity _      = False

-- | div and mod
divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod y x m = do
    i <- inverse (x `mod` m) m
    return $ y * i `mod` m
