{-# LANGUAGE OverloadedStrings #-}
module Main where

import Crypto.KDF.PBKDF2
import Data.ByteString as B
import Data.ByteString.Base16 (decode)
import Data.ByteString.Char8 as C8
import Test.Tasty
import Test.Tasty.HUnit

unhex :: ByteString -> ByteString
unhex = fst . decode

type CryptoFn = ByteString -> ByteString -> Int -> Int -> ByteString

testVectors :: CryptoFn -> [(C8.ByteString, C8.ByteString,Int,ByteString)] -> Assertion
testVectors _ [] = return ()
testVectors fn ((input, salt, iter, expected_hex):xs) = do
  let actual = fn input salt iter (floor ((fromIntegral $ B.length expected_hex) / fromIntegral 2))
  actual @?= (unhex expected_hex)
  testVectors fn xs

----------------------------------------------------------------------
main :: IO ()
main = do
  defaultMainWithIngredients defaultIngredients $
    testGroup "Test Vectors" $ [
        testCase "RFC6070 SHA1 Test Vectors"   (testVectors fastpbkdf2_hmac_sha1   test_vectors_sha1)
      , testCase "RFC6070 SHA256 Test Vectors" (testVectors fastpbkdf2_hmac_sha256 test_vectors_sha256)
      ]

-- RFC6070 test vectors
test_vectors_sha1 :: [(C8.ByteString,C8.ByteString,Int,ByteString)]
test_vectors_sha1 = [ ("password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6")
                    , ("password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
                    , ("password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1")
                    , ("password", "salt", 16777216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984")
                    , ( "passwordPASSWORDpassword"
                      , "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                      , 4096
                      , "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
                    , ("pass\0word", "sa\0lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3")
                    ]

test_vectors_sha256 :: [(C8.ByteString,C8.ByteString,Int,ByteString)]
test_vectors_sha256 = [ ("password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c9")
                    , ("password", "salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8e")
                    , ("password", "salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a0")
                    , ("password", "salt", 16777216, "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e8")
                    , ( "passwordPASSWORDpassword"
                      , "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                      , 4096
                      , "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c")
                    , ("pass\0word", "sa\0lt", 4096, "89b69d0516f829893c696226650a8687")
                    ]
