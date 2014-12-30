-- Test vectors are taken from GEC2: www.secg.org/collateral/gec2.pdf
{-# LANGUAGE OverloadedStrings #-}
module KAT.ECDSA (ecdsaTests) where

import Data.ByteString (ByteString)

import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Hash.SHA1 as SHA1

import Test.HUnit
import Test.Framework (testGroup)
import Test.Framework.Providers.HUnit (testCase)

data VectorECDSA = VectorECDSA
    { curve :: ECC.Curve
    , msg   :: ByteString
    , d     :: Integer
    , q     :: ECC.Point
    , k     :: Integer
    , r     :: Integer
    , s     :: Integer
    }

vectorsSHA1 =
    [ VectorECDSA
        { curve = ECC.getCurveByName ECC.SEC_p160r1
        , msg   = "abc"
        , d     = 971761939728640320549601132085879836204587084162
        , q     = ECC.Point 466448783855397898016055842232266600516272889280
                            1110706324081757720403272427311003102474457754220
        , k     = 702232148019446860144825009548118511996283736794
        , r     = 1176954224688105769566774212902092897866168635793
        , s     = 299742580584132926933316745664091704165278518100
        }
    , VectorECDSA
        { curve = ECC.getCurveByName ECC.SEC_t163k1
        , msg   = "abc"
        , d     = 5321230001203043918714616464614664646674949479949
        , q     = ECC.Point 0x037d529fa37e42195f10111127ffb2bb38644806bc
                            0x0447026eee8b34157f3eb51be5185d2be0249ed776
        , k     = 936523985789236956265265265235675811949404040044
        , r     = 875196600601491789979810028167552198674202899628
        , s     = 1935199835333115956886966454901154618180070051199
        }
    ]

vectorToPrivate :: VectorECDSA -> ECDSA.PrivateKey
vectorToPrivate vector = ECDSA.PrivateKey (curve vector) (d vector)

vectorToPublic :: VectorECDSA -> ECDSA.PublicKey
vectorToPublic vector = ECDSA.PublicKey (curve vector) (q vector)

doSignatureTest (i, vector) = testCase (show i) (expected @=? actual)
  where expected = Just $ ECDSA.Signature (r vector) (s vector)
        actual   = ECDSA.signWith (k vector) (vectorToPrivate vector) SHA1.hash (msg vector)

doVerifyTest (i, vector) = testCase (show i) (True @=? actual)
  where actual = ECDSA.verify SHA1.hash (vectorToPublic vector) (ECDSA.Signature (r vector) (s vector)) (msg vector)

ecdsaTests = testGroup "ECDSA"
    [ testGroup "SHA1"
        [ testGroup "signature" $ map doSignatureTest (zip [0..] vectorsSHA1)
        , testGroup "verify" $ map doVerifyTest (zip [0..] vectorsSHA1)
        ]
    ]
