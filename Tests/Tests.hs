{-# LANGUAGE OverloadedStrings #-}

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Test.QuickCheck
import Test.QuickCheck.Test
import System.IO (hFlush, stdout)

import Control.Monad
import Control.Arrow (first)
import Control.Applicative ((<$>))

import Data.List (intercalate)
import Data.Char
import Data.Bits
import Data.Word
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSAPKCS15
import qualified Crypto.PubKey.RSA.OAEP as RSAOAEP
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.DH as DH
import Crypto.Number.Serialize (i2osp)
import Crypto.PubKey.HashDescr

import qualified Crypto.Hash.SHA1 as SHA1
import RNG
import KAT
import PregenKeys

withAleasInteger :: Rng -> Seed -> (Rng -> (a,Rng)) -> a
withAleasInteger rng (Seed i) f = fst $ f $ reseed (i2osp (if i < 0 then -i else i)) rng

withRNG :: Seed -> (Rng -> (a,Rng)) -> a
withRNG seed f = withAleasInteger rng seed f

--withArbitraryRNG :: (Rng -> (a,Rng)) -> Arbitrary a
withArbitraryRNG f = arbitrary >>= \seed -> return (withAleasInteger rng seed f)

newtype PositiveSmall = PositiveSmall Integer
                      deriving (Show,Eq)

instance Arbitrary PositiveSmall where
    arbitrary = PositiveSmall `fmap` (resize (2^5) (arbitrarySizedIntegral `suchThat` (\i -> i > 0 && i < 2^5)))

data Range = Range Integer Integer
           deriving (Show,Eq)

instance Arbitrary Range where
    arbitrary = do x <- resize (2^30) (arbitrarySizedIntegral `suchThat` (\i -> i >= 40000 && i < 2^30))
                   o <- resize (2^10) (arbitrarySizedIntegral `suchThat` (\i -> i >= 1000 && i < 2^10))
                   return $ Range x (x+o)

newtype Seed = Seed Integer
             deriving (Eq)

instance Show Seed where
    show s = "Seed " ++ show s -- "seed"

instance Arbitrary Seed where
    arbitrary = Seed `fmap` (resize (2^30) (arbitrarySizedIntegral `suchThat` (\x -> x > 2^6 && x < 2^30)))

data RSAMessage = RSAMessage RSA.Blinder B.ByteString deriving (Show, Eq)

data RSAOAEPMessage = RSAOAEPMessage RSA.Blinder B.ByteString RSAOAEP.OAEPParams

instance Show RSAOAEPMessage where
    show (RSAOAEPMessage a1 b1 _) = "RSAOAEPMessage " ++ show a1 ++ " " ++ show b1

instance Eq RSAOAEPMessage where
    (RSAOAEPMessage a1 b1 _) == (RSAOAEPMessage a2 b2 _) = a1 == a2 && b1 == b2

genBS :: Int -> Gen B.ByteString
genBS sz = (B.pack . map fromIntegral) `fmap` replicateM sz (choose (0,255) :: Gen Int)

instance Arbitrary RSAOAEPMessage where
    arbitrary = do
        let hashLen = B.length (SHA1.hash B.empty)
        sz <- choose (0, 128 - 2*hashLen - 2)
        blinder <- withArbitraryRNG (\g -> RSA.generateBlinder g (RSA.public_n rsaPublickey))
        ws <- genBS sz
        return $ RSAOAEPMessage blinder ws (RSAOAEP.defaultOAEPParams SHA1.hash)

instance Arbitrary RSAMessage where
    arbitrary = do
        sz <- choose (0, 128 - 11)
        blinder <- withArbitraryRNG (\g -> RSA.generateBlinder g (RSA.public_n rsaPublickey))
        ws <- genBS sz
        return $ RSAMessage blinder ws

prop_rsa_pkcs15_valid fast blinding (RSAMessage blindR msg) =
    (either Left (doDecrypt pk) $ fst $ RSAPKCS15.encrypt rng rsaPublickey msg) == Right msg
    where pk = if fast then rsaPrivatekey else rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }
          doDecrypt = RSAPKCS15.decrypt (if blinding then Just blindR else Nothing)

prop_rsa_oaep_valid fast blinding (RSAOAEPMessage blindR msg oaepParams) =
    (either Left (doDecrypt oaepParams pk) $ fst $ RSAOAEP.encrypt rng oaepParams rsaPublickey msg) `assertEq` Right msg
    where pk        = if fast then rsaPrivatekey else rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }
          doDecrypt = RSAOAEP.decrypt (if blinding then Just blindR else Nothing)

assertEq (Right got) (Right exp) = if got == exp then True else error ("got: " ++ show got ++ "\nexp: " ++ show exp)
assertEq (Left got) (Right exp) = error ("got Left: " ++ show got)

prop_rsa_sign_valid fast (RSAMessage _ msg) = (either (const False) (\smsg -> verify msg smsg) $ sign msg) == True
    where
        verify   = RSAPKCS15.verify hashDescrSHA1 rsaPublickey
        sign     = RSAPKCS15.sign Nothing hashDescrSHA1 pk
        pk       = if fast then rsaPrivatekey else rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }

prop_rsa_sign_fast_valid = prop_rsa_sign_valid True
prop_rsa_sign_slow_valid = prop_rsa_sign_valid False

prop_dsa_valid (RSAMessage _ msg) = DSA.verify (SHA1.hash) dsaPublickey signature msg
    where (signature, rng') = DSA.sign rng dsaPrivatekey (SHA1.hash) msg

instance Arbitrary DH.PrivateNumber where
    arbitrary = fromIntegral <$> (suchThat (arbitrary :: Gen Integer) (\x -> x >= 1))

prop_dh_valid (xa, xb) = sa == sb
    where
        sa = DH.getShared dhparams xa yb
        sb = DH.getShared dhparams xb ya
        yb = DH.generatePublic dhparams xb
        ya = DH.generatePublic dhparams xa
        dhparams = (11, 7)


asymEncryptionTests = testGroup "assymmetric cipher encryption"
    [ testProperty "RSA(PKCS15) (slow)" (prop_rsa_pkcs15_valid False False)
    , testProperty "RSA(PKCS15) (fast)" (prop_rsa_pkcs15_valid True  False)
    , testProperty "RSA(PKCS15) (slow+blind)" (prop_rsa_pkcs15_valid False True)
    , testProperty "RSA(PKCS15) (fast+blind)" (prop_rsa_pkcs15_valid True  True)
    , testProperty "RSA(OAEP) (slow)" (prop_rsa_oaep_valid False False)
    , testProperty "RSA(OAEP) (fast)" (prop_rsa_oaep_valid True  False)
    , testProperty "RSA(OAEP) (slow+blind)" (prop_rsa_oaep_valid False True)
    , testProperty "RSA(OAEP) (fast+blind)" (prop_rsa_oaep_valid True  True)
    ]

asymSignatureTests = testGroup "assymmetric cipher signature"
    [ testProperty "RSA(PKCS15) (slow)" prop_rsa_sign_slow_valid
    , testProperty "RSA(PKCS15) (fast)" prop_rsa_sign_fast_valid
    , testProperty "DSA" prop_dsa_valid
    ]

asymOtherTests = testGroup "assymetric other tests"
    [ testProperty "DH valid" prop_dh_valid
    ]

main = defaultMain
    [ asymEncryptionTests
    , asymSignatureTests
    , asymOtherTests
    , testGroup "KATs" katTests
    ]
