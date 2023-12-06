WGET?=wget
TAR?=tar

LIBSODIUM_VERSION:=1.0.19
LIBSODIUM_TARBALL:=libsodium-$(LIBSODIUM_VERSION).tar.gz

.PHONY: libsodium
libsodium: libsodium/libsodium.a

libsodium/libsodium.a: libsodium/Makefile
	$(MAKE) -C libsodium

libsodium/Makefile: libsodium/marker
	cd libsodium && ./configure --prefix=$(abspath ..) --enable-opt --disable-shared

libsodium/marker: $(LIBSODIUM_TARBALL)
	rm -rf libsodium
	tar -xzf $(LIBSODIUM_TARBALL)
	mv libsodium-stable libsodium
	touch libsodium/marker

$(LIBSODIUM_TARBALL):
	wget -O $@ https://github.com/jedisct1/libsodium/releases/download/$(LIBSODIUM_VERSION)-RELEASE/$(LIBSODIUM_TARBALL)

.PHONY: clean
clean:
	rm -rf libsodium
	rm -rf libsodium-stable
	rm -f $(LIBSODIUM_TARBALL)
