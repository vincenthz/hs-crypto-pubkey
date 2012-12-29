{-# LANGUAGE OverloadedStrings #-}
module KAT.OAEP (oaepTests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Crypto.PubKey.RSA
import Crypto.PubKey.MaskGenFunction
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import qualified Crypto.Hash.SHA1 as SHA1

import Test.HUnit
import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.HUnit (testCase)

rsaKeyInt = PrivateKey
    { private_pub = PublicKey
        { public_n = 0xbbf82f090682ce9c2338ac2b9da871f7368d07eed41043a440d6b6f07454f51fb8dfbaaf035c02ab61ea48ceeb6fcd4876ed520d60e1ec4619719d8a5b8b807fafb8e0a3dfc737723ee6b4b7d93a2584ee6a649d060953748834b2454598394ee0aab12d7b61a51f527a9a41f6c1687fe2537298ca2a8f5946f8e5fd091dbdcb
        , public_e = 0x11 
        , public_size = 128
        }
    , private_d = 0xa5dafc5341faf289c4b988db30c1cdf83f31251e0668b42784813801579641b29410b3c7998d6bc465745e5c392669d6870da2c082a939e37fdcb82ec93edac97ff3ad5950accfbc111c76f1a9529444e56aaf68c56c092cd38dc3bef5d20a939926ed4f74a13eddfbe1a1cecc4894af9428c2b7b8883fe4463a4bc85b1cb3c1
    , private_p = 0xeecfae81b1b9b3c908810b10a1b5600199eb9f44aef4fda493b81a9e3d84f632124ef0236e5d1e3b7e28fae7aa040a2d5b252176459d1f397541ba2a58fb6599
    , private_q = 0xc97fb1f027f453f6341233eaaad1d9353f6c42d08866b1d05a0f2035028b9d869840b41666b42e92ea0da3b43204b5cfce3352524d0416a5a441e700af461503
    , private_dP = 0x54494ca63eba0337e4e24023fcd69a5aeb07dddc0183a4d0ac9b54b051f2b13ed9490975eab77414ff59c1f7692e9a2e202b38fc910a474174adc93c1f67c981
    , private_dQ = 0x471e0290ff0af0750351b7f878864ca961adbd3a8a7e991c5c0556a94c3146a7f9803f8f6f8ae342e931fd8ae47a220d1b99a495849807fe39f9245a9836da3d
    , private_qinv = 0xb06c4fdabb6301198d265bdbae9423b380f271f73453885093077fcd39e2119fc98632154f5883b167a967bf402b4e9e2e0f9656e698ea3666edfb25798039f7
    }

data VectorOAEP = VectorOAEP { seed :: ByteString
                             , message :: ByteString
                             , cipherText :: ByteString
                             }
vectorInt = VectorOAEP
    { message = "\xd4\x36\xe9\x95\x69\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49"
    , seed    = "\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f"
    , cipherText = "\x12\x53\xe0\x4d\xc0\xa5\x39\x7b\xb4\x4a\x7a\xb8\x7e\x9b\xf2\xa0\x39\xa3\x3d\x1e\x99\x6f\xc8\x2a\x94\xcc\xd3\x00\x74\xc9\x5d\xf7\x63\x72\x20\x17\x06\x9e\x52\x68\xda\x5d\x1c\x0b\x4f\x87\x2c\xf6\x53\xc1\x1d\xf8\x23\x14\xa6\x79\x68\xdf\xea\xe2\x8d\xef\x04\xbb\x6d\x84\xb1\xc3\x1d\x65\x4a\x19\x70\xe5\x78\x3b\xd6\xeb\x96\xa0\x24\xc2\xca\x2f\x4a\x90\xfe\x9f\x2e\xf5\xc9\xc1\x40\xe5\xbb\x48\xda\x95\x36\xad\x87\x00\xc8\x4f\xc9\x13\x0a\xde\xa7\x4e\x55\x8d\x51\xa7\x4d\xdf\x85\xd8\xb5\x0d\xe9\x68\x38\xd6\x06\x3e\x09\x55"
    }

doEncryptionTest key (i, vector) = testCase (show i) (Right (cipherText vector) @=? actual)
    where actual = OAEP.encryptWithSeed (seed vector) (OAEP.defaultOAEPParams SHA1.hash) key (message vector) 

doDecryptionTest key (i, vector) = testCase (show i) (Right (message vector) @=? actual)
    where actual = OAEP.decrypt (OAEP.defaultOAEPParams SHA1.hash) key (cipherText vector)

oaepTests = testGroup "RSA-OAEP"
    [ testGroup "encryption internal"
        [ doEncryptionTest (private_pub rsaKeyInt) (0, vectorInt)
        , doDecryptionTest rsaKeyInt (0, vectorInt)
        ]
    ]
