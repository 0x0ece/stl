.PHONY: deps
deps: lib/libsodium.a

lib/libsodium.a:
	$(MAKE) -C src libsodium
	$(MAKE) -C src/libsodium install

clean:
	$(MAKE) -C src clean
	rm -rf lib include
