# CryptoPill

CryptoPill is the crypto code used by [Core Secret](http://coresecret.io). This is a standalone crypto library heavily relying on the crypto primitives introduced by [NaCl](http://nacl.cr.yp.to/).


## Install

CryptoPill depends on [libsodium](https://github.com/jedisct1/libsodium) but this library is not directly provided by CryptoPill and must instead be included as a submodule. Follow these instructions to clone it and keep it in sync.

### Clone and compile libsodium

    # Add libsodium as Git submodule
    git submodule add git://github.com/jedisct1/libsodium.git libsodium
    git submodule init

    # Build libsodium
    ./libsodium.sh

    # CryptoPill's static lib file and headers are copied to libsodium_dist/
    # - Headers from the libsodium_dist/include/sodium/ directory are added to the Xcode project under the group CryptoPill/sodium/
    # - A dependancy on libsodium.a is added to the Xcode project

    # Later, to update libsodium just run these commands and if needed update its headers in Xcode to keep libsodium in sync
    cd libsodium && git pull

### Compile CryptoPill

Open this project in Xcode (Xcode 5 is the Xcode's version currently used), compile it and run its tests. It is then possible to include this project in a Xcode workspace to use it for his own project.


## Open source projects used by CryptoPill

* [libsodium](https://github.com/jedisct1/libsodium)
* [ed25519/ref](http://bench.cr.yp.to/supercop.html)
* [FEC](http://info.iet.unipi.it/~luigi/fec.html)
* [scrypt](http://www.tarsnap.com/scrypt.html)
* [HKDF](http://tools.ietf.org/html/rfc6234)


## License

The open source projects included above have their own license terms, please refer to their header files to see their licenses in details. Other than that the CryptoPill's code is licensed under the MIT license.
