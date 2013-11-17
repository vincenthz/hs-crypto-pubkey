-- | Signature generation.
module Crypto.PubKey.ECC.Generate where

import Crypto.Random (CPRG)
import Crypto.Types.PubKey.ECC
import Crypto.Types.PubKey.ECDSA
import Crypto.Number.Generate
import Crypto.PubKey.ECC.Prim

-- | Generate Q given d.
--
-- /WARNING:/ Vulnerable to timing attacks.
generateQ :: Curve
          -> Integer
          -> Point
generateQ curve d = pointMul curve d g
  where g = ecc_g $ common_curve curve

-- | Generate a pair of (private, public) key.
--
-- /WARNING:/ Vulnerable to timing attacks.
generate :: CPRG g
         => g     -- ^ CPRG
         -> Curve -- ^ Elliptic Curve
         -> ((PublicKey, PrivateKey), g)
generate rng curve = ((PublicKey curve q, PrivateKey curve d), rng')
  where (d, rng') = generateBetween rng 1 (n - 1)
        q = generateQ curve d
        n = ecc_n $ common_curve curve
