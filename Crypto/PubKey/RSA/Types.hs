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

data Error =
      MessageSizeIncorrect      -- ^ the message to decrypt is not of the correct size (need to be == private_size)
    | MessageTooLong            -- ^ the message to encrypt is too long (>= private_size - 11)
    | MessageNotRecognized      -- ^ the message decrypted doesn't have a PKCS15 structure (0 2 .. 0 msg)
    | SignatureTooLong          -- ^ the signature generated through the hash is too long to process with this key
    deriving (Show,Eq)

