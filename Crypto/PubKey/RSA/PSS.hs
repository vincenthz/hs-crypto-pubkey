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
import Data.Maybe (fromJust)
import Data.Bits

sign :: CryptoRandomGen g => g -> PrivateKey -> Message -> (ByteString, g)
sign rng pk m = d 1 pk em
    where d = if private_p pk /= 0 && private_q pk /= 0 then dpFast else dpSlow

          mHash       = hash m
          (salt,rng') = getRandomBytes rng hashLen

          padding1 = "00..00"
          padding2 = "00..01"
          m'       = B.concat [padding1,mHash,salt]
          h        = hash m'
          db       = B.concat [padding2,salt]
          dbmask   = mgf h (B.length db)
          maskedDB = B.pack $ B.zipWith xor db dbmask
          em       = B.concat [maskedDB,h, B.singleton 0xbc]          

verify pk m = undefined

mgf1 hash hashLen seed len = loop B.empty 0
    where loop t counter =
            | B.length t >= len = B.take len t
            | otherwise         = let counterBS = fromJust $ i2ospOf 4 counter
                                      newT = t `B.append` hash (seed `B.append` counterBS)
                                   in loop newT (counter+4)
