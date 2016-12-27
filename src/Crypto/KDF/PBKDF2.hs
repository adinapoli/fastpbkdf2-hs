
module Crypto.KDF.PBKDF2 (
    fastpbkdf2_hmac_sha1
  , fastpbkdf2_hmac_sha256
  , fastpbkdf2_hmac_sha512
  ) where

import Data.ByteString
import Data.ByteString.Unsafe
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe

foreign import ccall "fastpbkdf2_hmac_sha1" c_fastpbkdf2_hmac_sha1 :: Signature

foreign import ccall "fastpbkdf2_hmac_sha256" c_fastpbkdf2_hmac_sha256 :: Signature

foreign import ccall "fastpbkdf2_hmac_sha512" c_fastpbkdf2_hmac_sha512 :: Signature

type Signature = Ptr CChar -> CSize -> Ptr CChar -> CSize -> CInt -> Ptr CChar -> CSize -> IO ()

fastpbkdf2_fn :: Signature
              -> ByteString
              -- ^ The user key (e.g. a password)
              -> ByteString
              -- ^ The salt
              -> Int
              -- ^ The iteration count
              -> Int
              -- ^ The length (in bytes) of the output
              -> ByteString
fastpbkdf2_fn fn password salt iterations keyLen = unsafeDupablePerformIO $ do
  let outSize = CSize (fromIntegral keyLen)
  outForeignPtr <- mallocForeignPtrBytes keyLen
  withForeignPtr outForeignPtr $ \ptrOut -> do
    unsafeUseAsCStringLen password $ \(passwordPtr, passwordSizeInt) -> do
      unsafeUseAsCStringLen salt   $ \(saltPtr, saltSizeInt) -> do
        let passwordSize = CSize (fromIntegral passwordSizeInt)
        let saltSize     = CSize (fromIntegral saltSizeInt)
        let iters        = CInt (fromIntegral iterations)
        fn passwordPtr passwordSize saltPtr saltSize iters ptrOut outSize
        unsafePackCStringLen (ptrOut, keyLen)
{-# NOINLINE fastpbkdf2_fn #-}

--------------------------------------------------------------------------------
fastpbkdf2_hmac_sha1 :: ByteString
                     -- ^ The user key (e.g. a password)
                     -> ByteString
                     -- ^ The salt
                     -> Int
                     -- ^ The iteration count
                     -> Int
                     -- ^ The length (in bytes) of the output
                     -> ByteString
fastpbkdf2_hmac_sha1 = fastpbkdf2_fn c_fastpbkdf2_hmac_sha1
{-# NOINLINE fastpbkdf2_hmac_sha1 #-}

--------------------------------------------------------------------------------
fastpbkdf2_hmac_sha256 :: ByteString
                     -- ^ The user key (e.g. a password)
                     -> ByteString
                     -- ^ The salt
                     -> Int
                     -- ^ The iteration count
                     -> Int
                     -- ^ The length (in bytes) of the output
                     -> ByteString
fastpbkdf2_hmac_sha256 = fastpbkdf2_fn c_fastpbkdf2_hmac_sha256
{-# NOINLINE fastpbkdf2_hmac_sha256 #-}

--------------------------------------------------------------------------------
fastpbkdf2_hmac_sha512 :: ByteString
                     -- ^ The user key (e.g. a password)
                     -> ByteString
                     -- ^ The salt
                     -> Int
                     -- ^ The iteration count
                     -> Int
                     -- ^ The length (in bytes) of the output
                     -> ByteString
fastpbkdf2_hmac_sha512 = fastpbkdf2_fn c_fastpbkdf2_hmac_sha512
{-# NOINLINE fastpbkdf2_hmac_sha512 #-}
