module Crypto.PubKey.RSA.PSS
    ( sign
    , verify
    ) where

import Crypto.Random
import Crypto.Types.PubKey.RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types
import Crypto.Number.Serialize (os2ip, i2ospOf)
import Data.Maybe (fromJust)
import Data.Bits (xor)

signWithSalt :: ByteString -> PrivateKey -> ByteString -> ByteString
signWithSalt salt pk m = d 1 pk em
    where d = if private_p pk /= 0 && private_q pk /= 0 then dpFast else dpSlow

          mHash    = hash m
          dbLen    = private_size pk - hashLen - 1
          saltLen  = B.length salt

          m'       = B.concat [B.replicate 8 0,mHash,salt]
          h        = hash m'
          db       = B.concat [B.replicate (dbLen - saltLen - 1) 0,B.singleton 1,salt]
          dbmask   = mgf1 hash hashLen h dbLen
          maskedDB = B.pack $ B.zipWith xor db dbmask
          em       = B.concat [maskedDB, h, B.singleton 0xbc]

{-
sign rng =
          (salt,rng') = getRandomBytes rng hashLen
-}

verify pk sLen m s
    | public_size pk /= B.length s = False
    | B.last em /= 0xbc            = False
    | not (B.all (== 0) ps0)       = False
    | b1 /= B.singleton 1          = False
    | otherwise                    = h == h'
        where em        = ep pk (os2ip s)
              maskedDB  = B.take (B.length em - hashLen - 1) em
              h         = B.take hashLen $ B.drop (B.length maskedDB) em
              dbmask    = mgf1 hash hashLen h
              db        = B.pack $ B.zipWith xor maskedDB dbmask
              (ps0,z)   = B.break (== 1)
              (b1,salt) = B.splitAt 1 z
              mHash     = hash m
              m'        = B.concat [B.replicate 8 0,mHash,salt]
              h'        = hash m'


mgf1 hash hashLen seed len = loop B.empty 0
    where loop t counter
            | B.length t >= len = B.take len t
            | otherwise         = let counterBS = fromJust $ i2ospOf 4 counter
                                      newT = t `B.append` hash (seed `B.append` counterBS)
                                   in loop newT (counter+4)
