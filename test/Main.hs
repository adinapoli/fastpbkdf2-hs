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

testVectors :: [(C8.ByteString, C8.ByteString,Int,ByteString)] -> Assertion
testVectors [] = return ()
testVectors ((input, salt, iter, expected_hex):xs) = do
  let actual = fastpbkdf2_hmac_sha1 input salt iter (floor ((fromIntegral $ B.length expected_hex) / fromIntegral 2))
  actual @?= (unhex expected_hex)
  testVectors xs

----------------------------------------------------------------------
main :: IO ()
main = do
  defaultMainWithIngredients defaultIngredients $
    testGroup "Test Vectors" $ [
      testCase "RFC6070 Test Vectors" (testVectors test_vectors)
      ]

-- RFC6070 test vectors
test_vectors :: [(C8.ByteString,C8.ByteString,Int,ByteString)]
test_vectors = [ ("password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6")
               , ("password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
               , ("password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1")
               , ("password", "salt", 16777216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984")
               , ( "passwordPASSWORDpassword"
                 , "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                 , 4096
                 , "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
               , ("pass\0word", "sa\0lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3")
               ]
