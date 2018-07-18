module Model.BCrypt
  ( module Model.BCrypt
  , module Import
  ) where

import Prelude

import Crypto.BCrypt as Import hiding (hashPassword)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import           Database.Persist.Sql
import           Safe (fromJustNote)
import Data.Time.Clock
import qualified Data.ByteString.Base16 as B16

policy :: HashingPolicy
policy = 
  HashingPolicy { preferredHashCost = 12
                , preferredHashAlgorithm = "$2a$"
                }

newtype BCrypt =
  BCrypt { unBCrypt ::  T.Text }
  deriving (Eq, PersistField, PersistFieldSql, Show)

hashPassword :: T.Text -> IO BCrypt
hashPassword rawPassword = do
  mPassword <- hashPasswordUsingPolicy policy $ TE.encodeUtf8 rawPassword
  return $ BCrypt $ TE.decodeUtf8 $ fromJustNote "Invalid hashing policy" mPassword

passwordMatches :: BCrypt -> T.Text -> Bool
passwordMatches hash' pass = 
  validatePassword (TE.encodeUtf8 $ unBCrypt hash')
                   (TE.encodeUtf8 pass)

-- I was curious how this would work out, will eventually delete
generateToken :: IO T.Text
generateToken = do
  timeText <- T.pack . show <$> getCurrentTime
  cryp <- hashPassword timeText
  return $ T.drop 80 . TE.decodeUtf8 . B16.encode . TE.encodeUtf8 $ unBCrypt cryp

