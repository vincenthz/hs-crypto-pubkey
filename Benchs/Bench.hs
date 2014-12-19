{-# LANGUAGE BangPatterns #-}
module Main where

import Criterion.Main
import PregenKeys

import qualified Crypto.Hash.SHA1 as SHA1
import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.PKCS15 as PKCS15
import Crypto.PubKey.RSA.OAEP as OAEP
import Crypto.PubKey.RSA.PSS as PSS
import Crypto.PubKey.HashDescr
import Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.PubKey.ECC.Prim as ECC
import Crypto.Types.PubKey.ECC as ECC
import Crypto.Random
import Control.DeepSeq

import qualified Data.ByteString as B

right (Right r) = r
right (Left _)  = error "left received"

instance NFData Signature where
    rnf (Signature r s) = rnf r `seq` rnf s

instance NFData Point where
    rnf PointO      = ()
    rnf (Point x y) = x `seq` y `seq` ()

pointN curve i = pointMul curve i g
  where common = ECC.common_curve curve
        g      = ECC.ecc_g common

main = do
    rng <- cprgCreate `fmap` createEntropyPool :: IO SystemRNG
    let !bs = B.replicate 32 0
        !encryptedMsgPKCS = (right . fst . PKCS15.encrypt rng rsaPublickey) bs
        !encryptedMsgOAEP = (right . fst . OAEP.encrypt rng oaepParams rsaPublickey) bs
        !signedMsgPKCS = (right . PKCS15.sign Nothing hashDescrSHA1 rsaPrivatekey) bs
        !signedMsgPSS = (right . fst . PSS.sign rng Nothing pssParams rsaPrivatekey) bs
        privateKeySlow = rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }
        !blinder = fst $ generateBlinder rng (RSA.public_n rsaPublickey)
        oaepParams = OAEP.defaultOAEPParams SHA1.hash
        pssParams  = PSS.defaultPSSParamsSHA1
        ecdsaSignatureP = fst $ ECDSA.sign rng ecdsaPrivatekeyP SHA1.hash bs
        ecdsaSignatureB = fst $ ECDSA.sign rng ecdsaPrivatekeyB SHA1.hash bs

        !pointP1P = pointN ecdsaCurveP 5
        !pointP2P = pointN ecdsaCurveP 9
        !pointP1B = pointN ecdsaCurveB 5
        !pointP2B = pointN ecdsaCurveB 9
    defaultMain
        [ bgroup "RSA"
            [ bgroup "PKCS15"
                [ bench "encryption" $ nf (right . fst . PKCS15.encrypt rng rsaPublickey) bs
                , bgroup "decryption"
                    [ bench "slow" $ nf (right . PKCS15.decrypt Nothing privateKeySlow) encryptedMsgPKCS
                    , bench "fast" $ nf (right . PKCS15.decrypt Nothing rsaPrivatekey) encryptedMsgPKCS
                    , bench "slow+blinding" $ nf (right . PKCS15.decrypt (Just blinder) privateKeySlow) encryptedMsgPKCS
                    , bench "fast+blinding" $ nf (right . PKCS15.decrypt (Just blinder) rsaPrivatekey) encryptedMsgPKCS
                    ]
                , bgroup "signing"
                    [ bench "slow" $ nf (right . PKCS15.sign Nothing hashDescrSHA1 privateKeySlow) bs
                    , bench "fast" $ nf (right . PKCS15.sign Nothing hashDescrSHA1 rsaPrivatekey) bs
                    , bench "slow+blinding" $ nf (right . PKCS15.sign (Just blinder) hashDescrSHA1 privateKeySlow) bs
                    , bench "fast+blinding" $ nf (right . PKCS15.sign (Just blinder) hashDescrSHA1 rsaPrivatekey) bs
                    ]
                , bench "verify" $ nf (PKCS15.verify hashDescrSHA1 rsaPublickey bs) signedMsgPKCS
                ]
            , bgroup "OAEP"
                [ bench "encryption" $ nf (right . fst . OAEP.encrypt rng oaepParams rsaPublickey) bs
                , bgroup "decryption"
                    [ bench "slow" $ nf (right . OAEP.decrypt Nothing oaepParams privateKeySlow) encryptedMsgOAEP
                    , bench "fast" $ nf (right . OAEP.decrypt Nothing oaepParams rsaPrivatekey) encryptedMsgOAEP
                    , bench "slow+blinding" $ nf (right . OAEP.decrypt (Just blinder) oaepParams privateKeySlow) encryptedMsgOAEP
                    , bench "fast+blinding" $ nf (right . OAEP.decrypt (Just blinder) oaepParams rsaPrivatekey) encryptedMsgOAEP
                    ]
                ]
            , bgroup "PSS"
                [ bgroup "signing"
                    [ bench "slow" $ nf (right . fst . PSS.sign rng Nothing pssParams privateKeySlow) bs
                    , bench "fast" $ nf (right . fst . PSS.sign rng Nothing pssParams rsaPrivatekey) bs
                    , bench "slow+blinding" $ nf (right . fst . PSS.sign rng (Just blinder) pssParams privateKeySlow) bs
                    , bench "fast+blinding" $ nf (right . fst . PSS.sign rng (Just blinder) pssParams rsaPrivatekey) bs
                    ]
                , bench "verify" $ nf (PSS.verify pssParams rsaPublickey bs) signedMsgPSS
                ]
            ]
        , bgroup "ECC"
            [ bgroup "add"
                [ bench "prime" $ nf (ECC.pointAdd ecdsaCurveP pointP1P) pointP2P
                , bench "binary" $ nf (ECC.pointAdd ecdsaCurveB pointP1B) pointP2B
                ]
            , bgroup "mul"
                [ bench "prime * 5" $ nf (\i -> ECC.pointMul ecdsaCurveP i pointP1P) 5
                , bench "prime * 1234" $ nf (\i -> ECC.pointMul ecdsaCurveP i pointP1P) 1234
                , bench "binary * 5" $ nf (\i -> ECC.pointMul ecdsaCurveB i pointP1B) 5
                , bench "binary * 1234" $ nf (\i -> ECC.pointMul ecdsaCurveB i pointP1B) 1234
                ]
            ]
        , bgroup "ECDSA"
            [ bgroup "secp160r1"
                [ bench "sign" $ nf (fst . ECDSA.sign rng ecdsaPrivatekeyP SHA1.hash) bs
                , bench "verify"  $ nf (ECDSA.verify SHA1.hash ecdsaPublickeyP ecdsaSignatureP) bs
                ]
            , bgroup "sect163k1"
                [ bench "sign" $ nf (fst . ECDSA.sign rng ecdsaPrivatekeyB SHA1.hash) bs
                , bench "verify"  $ nf (ECDSA.verify SHA1.hash ecdsaPublickeyB ecdsaSignatureB) bs
                ]
            ]
        ]
