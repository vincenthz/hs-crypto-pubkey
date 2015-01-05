module EccArithmetic (properties_ecc_arithmetic) where

import Test.Tasty.QuickCheck

import Crypto.Types.PubKey.ECC
import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Prim

data GeneratePoint1 = GeneratePoint1 Curve Point
    deriving (Show,Eq)
data GeneratePoint2 = GeneratePoint2 Curve Point Point
    deriving (Show,Eq)

arbitraryPoint curve = do
    sec <- choose (1,n)
    return $ pointMul curve sec g
  where common = common_curve curve
        n      = ecc_n common
        g      = ecc_g common

instance Arbitrary Curve where
    arbitrary = elements $ map getCurveByName $ enumFrom SEC_p112r1

instance Arbitrary GeneratePoint1 where
    arbitrary = do
        curve <- arbitrary
        p1    <- arbitraryPoint curve
        return $ GeneratePoint1 curve p1

instance Arbitrary GeneratePoint2 where
    arbitrary = do
        curve <- arbitrary
        p1    <- arbitraryPoint curve
        p2    <- arbitraryPoint curve
        return $ GeneratePoint2 curve p1 p2

properties_ecc_arithmetic =
    [ testProperty "commutative" $ \(GeneratePoint2 curve p1 p2) ->
        pointAdd curve p1 p2 == pointAdd curve p2 p1
    , testProperty "add-neutral" $ \(GeneratePoint1 curve p1) -> pointAdd curve p1 PointO == p1
    ]
