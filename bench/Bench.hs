{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PackageImports #-}
module Main where

import              Criterion.Main
import              Crypto.Hash.Algorithms as Crypto
import "cryptonite" Crypto.KDF.PBKDF2 as Crypto
import "fastpbkdf2" Crypto.KDF.PBKDF2 as Fast
import              Crypto.PBKDF.ByteString as CD
import              Data.ByteString as B

data Library = FastPBKDF2
             | Cryptonite
             | PBKDF2

encryptBench :: Library -> ByteString -> ByteString
encryptBench FastPBKDF2 input = Fast.fastpbkdf2_hmac_sha1 input "salt" 10000 32
encryptBench Cryptonite input = Crypto.generate (Crypto.prfHMAC Crypto.SHA1) (Crypto.Parameters 10000 32) input ("salt" :: ByteString)
encryptBench PBKDF2     input = CD.sha1PBKDF2 input "salt" 10000 32

main :: IO ()
main = defaultMain [
  bgroup "sha1" [ bench "fastpbkdf2"  $ whnf (encryptBench FastPBKDF2) (B.pack $ Prelude.replicate 100000 0x0)
                , bench "cryptonite"  $ whnf (encryptBench Cryptonite) (B.pack $ Prelude.replicate 100000 0x0)
                , bench "pbkdf2"      $ whnf (encryptBench PBKDF2)     (B.pack $ Prelude.replicate 100000 0x0)
                ]
  ]
