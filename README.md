[![Build Status](https://travis-ci.org/adinapoli/fastpbkdf2-hs.svg?branch=master)](https://travis-ci.org/adinapoli/fastpbkdf2-hs)
[![Build status](https://ci.appveyor.com/api/projects/status/vj3d35qptms3q23w?svg=true)](https://ci.appveyor.com/project/adinapoli/rncryptor-hs)
[![Coverage Status](https://coveralls.io/repos/github/adinapoli/fastpbkdf2-hs/badge.svg?branch=master)](https://coveralls.io/github/adinapoli/fastpbkdf2-hs?branch=master)

## fastpbkdf2-hs

Haskell bindings to the [fastpbkdf2](https://github.com/ctz/fastpbkdf2) library.

### Installation

This library depends from `OpenSSL`. I have tried to make this self-contained, but the
crypto layer of OpenSSL (or BoringSSL) requires some fine-tuned ASM code generated during
the build process. Porting everything over in a customised `Build.hs` would have been too
much pain, but PR are super welcome!
