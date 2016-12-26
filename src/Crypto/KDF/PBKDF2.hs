
module Crypto.KDF.PBKDF2 where

import Data.ByteString
import Data.ByteString.Unsafe
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe

foreign import ccall "fastpbkdf2_hmac_sha1" c_fastpbkdf2_hmac_sha1 ::
  Ptr CChar -> CSize -> Ptr CChar -> CSize -> CInt -> Ptr CChar -> CSize -> IO ()

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
fastpbkdf2_hmac_sha1 password salt iterations keyLen = unsafeDupablePerformIO $ do
  let outSize = CSize (fromIntegral keyLen)
  outForeignPtr <- mallocForeignPtrBytes keyLen
  withForeignPtr outForeignPtr $ \ptrOut -> do
    unsafeUseAsCStringLen password $ \(passwordPtr, passwordSizeInt) -> do
      unsafeUseAsCStringLen salt   $ \(saltPtr, saltSizeInt) -> do
        let passwordSize = CSize (fromIntegral passwordSizeInt)
        let saltSize     = CSize (fromIntegral saltSizeInt)
        let iters        = CInt (fromIntegral iterations)
        c_fastpbkdf2_hmac_sha1 passwordPtr passwordSize saltPtr saltSize iters ptrOut outSize
        unsafePackCStringLen (ptrOut, keyLen)
{-# NOINLINE fastpbkdf2_hmac_sha1 #-}

{--
void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                          const uint8_t *salt, size_t nsalt,
                          uint32_t iterations,
                          uint8_t *out, size_t nout);
--}

{--
void fastpbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout);
--}

{--
void fastpbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout);
--}
