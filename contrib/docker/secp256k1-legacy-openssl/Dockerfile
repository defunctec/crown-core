FROM gcc:5

WORKDIR /work/src/secp256k1

CMD ["bash", "-lc", "./configure && make -j\"$(nproc)\" tests && ./tests"]
