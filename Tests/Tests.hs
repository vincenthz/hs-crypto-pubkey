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
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.DH as DH
import Crypto.Number.Serialize (i2osp)

import qualified Crypto.Hash.SHA1 as SHA1
import RNG
import PregenKeys

withAleasInteger :: Rng -> Seed -> (Rng -> (a,Rng)) -> a
withAleasInteger rng (Seed i) f = fst $ f $ reseed (i2osp (if i < 0 then -i else i)) rng

withRNG :: Seed -> (Rng -> (a,Rng)) -> a
withRNG seed f = withAleasInteger rng seed f

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

data RSAMessage = RSAMessage Integer B.ByteString deriving (Show, Eq)

instance Arbitrary RSAMessage where
    arbitrary = do
        sz <- choose (0, 128 - 11)
        blinder <- choose (1, RSA.public_n rsaPublickey - 1)
        ws <- replicateM sz (choose (0,255) :: Gen Int)
        return $ RSAMessage blinder (B.pack $ map fromIntegral ws)

{-
prop_rsa_generate_valid (Positive i, RSAMessage msgz) =
    let keysz = 64 in
    let (pub,priv) = withAleasInteger rng i (\g -> RSA.generate g keysz 65537) in
    let msg = B.take (keysz - 11) msgz in
    (RSA.private_p priv * RSA.private_q priv == RSA.private_n priv) &&
    ((RSA.private_d priv * RSA.public_e pub) `mod` ((RSA.private_p priv - 1) * (RSA.private_q priv - 1)) == 1) &&
    (either Left (RSA.decrypt priv . fst) $ RSA.encrypt rng pub msg) == Right msg
-}
prop_rsa_valid fast blinding (RSAMessage blindR msg) =
    (either Left (doDecrypt pk . fst) $ RSA.encrypt rng rsaPublickey msg) == Right msg
    where pk = if fast then rsaPrivatekey else rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }
          doDecrypt = if blinding then RSA.decryptWithBlinding blindR else RSA.decrypt

prop_rsa_fast_valid  = prop_rsa_valid True
prop_rsa_slow_valid  = prop_rsa_valid False

prop_rsa_sign_valid fast (RSAMessage _ msg) = (either (const False) (\smsg -> verify msg smsg) $ sign msg) == True
    where
        verify   = RSA.verify (SHA1.hash) sha1desc rsaPublickey
        sign     = RSA.sign (SHA1.hash) sha1desc pk
        sha1desc = B.pack [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03, 0x02,0x1a,0x05,0x00,0x04,0x14]
        pk       = if fast then rsaPrivatekey else rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }

prop_rsa_sign_fast_valid = prop_rsa_sign_valid True
prop_rsa_sign_slow_valid = prop_rsa_sign_valid False

prop_dsa_valid (RSAMessage _ msg) =
    case DSA.verify signature (SHA1.hash) dsaPublickey msg of
        Left err -> False
        Right b  -> b
    where
        (signature, rng') = DSA.sign rng (SHA1.hash) dsaPrivatekey msg

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
    [ testProperty "RSA (slow)" (prop_rsa_valid False False)
    , testProperty "RSA (fast)" (prop_rsa_valid True  False)
    , testProperty "RSA (slow+blind)" (prop_rsa_valid False True)
    , testProperty "RSA (fast+blind)" (prop_rsa_valid True  True)
    ]

asymSignatureTests = testGroup "assymmetric cipher signature"
    [ testProperty "RSA (slow)" prop_rsa_sign_slow_valid
    , testProperty "RSA (fast)" prop_rsa_sign_fast_valid
    , testProperty "DSA" prop_dsa_valid
    ]

asymOtherTests = testGroup "assymetric other tests"
    [ testProperty "DH valid" prop_dh_valid
    ]

main = defaultMain
    [ asymEncryptionTests
    , asymSignatureTests
    , asymOtherTests
    ]
