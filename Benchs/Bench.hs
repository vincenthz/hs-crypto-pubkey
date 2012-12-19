{-# LANGUAGE BangPatterns #-}
module Main where

import Criterion.Main
import PregenKeys

import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.PKCS15 as PKCS15
import Crypto.PubKey.RSA.PSS as PSS
import Crypto.PubKey.HashDescr

import Crypto.Random.AESCtr
import qualified Data.ByteString as B

right (Right r) = r
right (Left _)  = error "left received"

main = do
    rng <- makeSystem
    let !bs = B.replicate 32 0
        !encryptedMsg = (fst . right . PKCS15.encrypt rng rsaPublickey) bs
        !signedMsg = (right . PKCS15.sign hashDescrSHA1 rsaPrivatekey) bs
        privateKeySlow = rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }
        blinder = 0x123
    defaultMain
        [ bench "RSA.PKCS15 encrypt" $ nf (fst . right . PKCS15.encrypt rng rsaPublickey) bs
        , bench "RSA.PKCS15 decrypt(slow)" $ nf (right . PKCS15.decrypt privateKeySlow) encryptedMsg
        , bench "RSA.PKCS15 decrypt(fast)" $ nf (right . PKCS15.decrypt rsaPrivatekey) encryptedMsg
        , bench "RSA.PKCS15 decrypt(slow+blinding)" $ nf (right . PKCS15.decryptWithBlinding blinder privateKeySlow) encryptedMsg
        , bench "RSA.PKCS15 decrypt(fast+blinding)" $ nf (right . PKCS15.decryptWithBlinding blinder rsaPrivatekey) encryptedMsg
        , bench "RSA.PKCS15 signing(slow)" $ nf (right . PKCS15.sign hashDescrSHA1 privateKeySlow) encryptedMsg
        , bench "RSA.PKCS15 signing(fast)" $ nf (right . PKCS15.sign hashDescrSHA1 rsaPrivatekey) encryptedMsg
        , bench "RSA.PKCS15 signing(slow+blinding)" $ nf (right . PKCS15.signWithBlinding blinder hashDescrSHA1 privateKeySlow) encryptedMsg
        , bench "RSA.PKCS15 signing(fast+blinding)" $ nf (right . PKCS15.signWithBlinding blinder hashDescrSHA1 rsaPrivatekey) encryptedMsg
        , bench "RSA.PKCS15 verify" $ nf (PKCS15.verify hashDescrSHA1 rsaPublickey bs) signedMsg
        ]
