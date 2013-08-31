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
import Crypto.Random

import qualified Data.ByteString as B

right (Right r) = r
right (Left _)  = error "left received"

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
    defaultMain
        [ bgroup "RSA PKCS15"
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
        , bgroup "RSA OAEP"
            [ bench "encryption" $ nf (right . fst . OAEP.encrypt rng oaepParams rsaPublickey) bs
            , bgroup "decryption"
                [ bench "slow" $ nf (right . OAEP.decrypt Nothing oaepParams privateKeySlow) encryptedMsgOAEP
                , bench "fast" $ nf (right . OAEP.decrypt Nothing oaepParams rsaPrivatekey) encryptedMsgOAEP
                , bench "slow+blinding" $ nf (right . OAEP.decrypt (Just blinder) oaepParams privateKeySlow) encryptedMsgOAEP
                , bench "fast+blinding" $ nf (right . OAEP.decrypt (Just blinder) oaepParams rsaPrivatekey) encryptedMsgOAEP
                ]
            ]
        , bgroup "RSA PSS"
            [ bgroup "signing"
                [ bench "slow" $ nf (right . fst . PSS.sign rng Nothing pssParams privateKeySlow) bs
                , bench "fast" $ nf (right . fst . PSS.sign rng Nothing pssParams rsaPrivatekey) bs
                , bench "slow+blinding" $ nf (right . fst . PSS.sign rng (Just blinder) pssParams privateKeySlow) bs
                , bench "fast+blinding" $ nf (right . fst . PSS.sign rng (Just blinder) pssParams rsaPrivatekey) bs
                ]
            , bench "verify" $ nf (PSS.verify pssParams rsaPublickey bs) signedMsgPSS
            ]
        ]
