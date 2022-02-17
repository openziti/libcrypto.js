#! /bin/sh

export PREFIX="$(pwd)/libcrypto-js"
export MAKE_FLAGS='-j4'

echo

emconfigure ./Configure \
  -m32 \
  linux-generic32 \
  --with-rand-seed=getrandom \
  no-asm \
  no-threads \
  no-engine \
  no-weak-ssl-ciphers \
  no-dtls \
  no-shared \
  no-dso \
  --prefix="$PREFIX" \
  CFLAGS="" && \
sed -i='' 's|^CROSS_COMPILE.*$|CROSS_COMPILE=|g' Makefile && \
sed -i='' '/^CFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile && \
sed -i='' '/^CXXFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile && \
emmake make clean
[ $? = 0 ] || exit 1

emmake make $MAKE_FLAGS build_generated || exit 1

echo "==========================================="
echo "'emconfigure' completed"
echo "==========================================="

