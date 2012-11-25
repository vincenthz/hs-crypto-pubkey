-- |
-- Module      : Crypto.PubKey.RSA.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.PubKey.RSA.Types
    ( Error(..)
    ) where

import Crypto.Random

data Error =
      MessageSizeIncorrect      -- ^ the message to decrypt is not of the correct size (need to be == private_size)
    | MessageTooLong            -- ^ the message to encrypt is too long (>= private_size - 11)
    | MessageNotRecognized      -- ^ the message decrypted doesn't have a PKCS15 structure (0 2 .. 0 msg)
    | SignatureTooLong          -- ^ the signature generated through the hash is too long to process with this key
    | RandomGenFailure GenError -- ^ the random generator returns an error. give the opportunity to reseed for example.
    | KeyInternalError          -- ^ the whole key is probably not valid, since the message is bigger than the key size
    deriving (Show,Eq)

