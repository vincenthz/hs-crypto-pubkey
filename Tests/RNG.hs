module RNG where

import Data.Word
import Data.List (foldl')
import Data.Byteable
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

instance CPRG Rng where
    cprgCreate pool = let ent = grabEntropy 4 pool in generate (B.unpack $ toBytes ent)
    cprgSetReseedThreshold _ g = g
    cprgGenerate len g = first B.pack $ getBytes len g
    cprgGenerateWithEntropy = cprgGenerate
    cprgFork g = let (bs, g') = getBytes 4 g
                    in case bs of
                        [a,b,c,d] -> let g2 = Rng (fromIntegral a * 256 + fromIntegral b, fromIntegral c * 256 + fromIntegral d)
                                      in (g2, g')
                        _         -> error "getBytes assertion"


generate :: [Word8] -> Rng
generate [a,b,c,d] = Rng (fromIntegral a * 256 + fromIntegral b, fromIntegral c * 256 + fromIntegral d)
generate _ = error "generate assertion: need 4 bytes"

reseed :: B.ByteString -> Rng -> Rng
reseed bs (Rng (a,b)) = Rng (fromIntegral a', b')
        where a' = foldl' (\v i -> ((fromIntegral v) + (fromIntegral i) * 36969) `mod` 65536) a l
              b' = foldl' (\v i -> ((fromIntegral v) + (fromIntegral i) * 18070) `mod` 65536) b l
              l  = B.unpack bs

rng :: Rng
rng = Rng (2,2)
