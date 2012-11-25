module RNG where

import Data.Word
import Data.List (foldl')
import qualified Data.ByteString as B
import Crypto.Random
import Control.Arrow (first)

{- this is a just test rng. this is absolutely not a serious RNG. DO NOT use elsewhere -}
data Rng = Rng (Int, Int)

getByte :: Rng -> (Word8, Rng)
getByte (Rng (mz, mw)) = (r, g)
    where mz2 = 36969 * (mz `mod` 65536)
          mw2 = 18070 * (mw `mod` 65536)
          r   = fromIntegral (mz2 + mw2)
          g   = Rng (mz2, mw2)

getBytes :: Int -> Rng -> ([Word8], Rng)
getBytes 0 g = ([], g)
getBytes n g =
    let (b, g')  = getByte g
        (l, g'') = getBytes (n-1) g'
     in (b:l, g'')

instance CryptoRandomGen Rng where
    newGen _       = Right (Rng (2,3))
    genSeedLength  = 0
    genBytes len g = Right $ first B.pack $ getBytes len g
    reseed bs (Rng (a,b)) = Right $ Rng (fromIntegral a', b')
        where a' = foldl' (\v i -> ((fromIntegral v) + (fromIntegral i) * 36969) `mod` 65536) a l
              b' = foldl' (\v i -> ((fromIntegral v) + (fromIntegral i) * 18070) `mod` 65536) b l
              l  = B.unpack bs

rng :: Rng
rng = Rng (1,2) 
