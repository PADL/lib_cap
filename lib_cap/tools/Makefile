DEPS = ../src/ed25519/ed25519-private.h ../src/ed25519/ed25519.h ../src/ed25519/fe.h ../src/ed25519/fixedint.h ../src/ed25519/precomp_data.h ../src/ed25519/sc.h ../src/ed25519/sha512.h base64.h
OBJ = ../src/ed25519/ed25519_ph.c ../src/ed25519/add_scalar.c ../src/ed25519/fe.c ../src/ed25519/ge.c ../src/ed25519/key_exchange.c ../src/ed25519/keypair.c ../src/ed25519/sc.c ../src/ed25519/seed.c ../src/ed25519/sha512.c ../src/ed25519/sign.c ../src/ed25519/verify.c xcaptool.c base64.c

CFLAGS = -Wall -g -I../src -I../src/ed25519

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

xcaptool: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f xcaptool *.o core

format:
	clang-format -i *.[ch]

