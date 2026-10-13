CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -g
CPPFLAGS ?= -I. -D_DEFAULT_SOURCE
LDFLAGS ?= -lpthread

TEST_DIR   = test
SRC_FILES  = sha.c aes.c bn.c rsa.c rsa_keygen.c dh.c ecc.c asn1.c x509.c rng.c ssl.c
OBJ_FILES  = $(SRC_FILES:.c=.o)
LIB        = libasslibc.a
HDRS       = asslibc.h ssl.h x509.h asn1.h

TESTS      = test_hash test_aes test_bn test_rsa test_dh test_ecc test_x509 \
             test_rng test_ssl test_tls13 test_tls12 test_ssl3 test_tls_pipe \
             test_x509_chain test_verify test_negative test_x509_strict test_x509_crl

TEST_BINS  = $(addprefix $(TEST_DIR)/,$(TESTS))

INTEROP    = interop_server interop_client
INTEROP_BINS = $(addprefix $(TEST_DIR)/,$(INTEROP))

FUZZ_DIR   = fuzz
FUZZERS    = fuzz_bn fuzz_rsa fuzz_x509
FUZZ_BINS  = $(addprefix $(FUZZ_DIR)/,$(FUZZERS))
FUZZ_CC   ?= clang
FUZZ_CFLAGS ?= -std=c11 -O1 -g -Wall -Wextra -I.

ASAN_CC    ?= clang
ASAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_LEAKS ?= 0

.PHONY: all clean test lib interop interop-test fuzz asan-test

all: $(TEST_BINS) $(INTEROP_BINS) $(LIB)

lib: $(LIB)

$(TEST_DIR)/%: $(TEST_DIR)/%.c $(SRC_FILES) $(HDRS) $(TEST_DIR)/test_cert.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(SRC_FILES) $(LDFLAGS)

$(TEST_DIR)/gen_cert: $(TEST_DIR)/gen_cert.c $(SRC_FILES) $(HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(SRC_FILES) $(LDFLAGS)

test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do echo "--- $$t"; ./$$t; done
	@echo "ALL TEST SUITES PASSED"

interop: $(INTEROP_BINS)

interop-test: $(INTEROP_BINS) $(TEST_DIR)/gen_cert
	@cd $(TEST_DIR) && ./interop.sh

fuzz: $(FUZZ_BINS)
	@echo "Fuzzers built. Run them, e.g.:"
	@echo "  $(FUZZ_DIR)/fuzz_bn -max_total_time=120"
	@echo "  $(FUZZ_DIR)/fuzz_rsa -runs=10000 -seed=1"

$(FUZZ_DIR)/%: $(FUZZ_DIR)/%.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer,address,undefined -o $@ $< $(SRC_FILES) $(LDFLAGS)

asan-test:
	@command -v $(ASAN_CC) >/dev/null || { echo "asan-test: $(ASAN_CC) not found"; exit 1; }
	@set -e; for t in $(TESTS); do \
	    $(ASAN_CC) $(CFLAGS) $(CPPFLAGS) $(ASAN_FLAGS) -o $(TEST_DIR)/asan-$$t $(TEST_DIR)/$$t.c $(SRC_FILES) $(LDFLAGS); \
	done; \
	for t in $(TESTS); do \
	    echo "--- asan $$t"; \
	    ASAN_OPTIONS=detect_leaks=$(ASAN_LEAKS) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./$(TEST_DIR)/asan-$$t; \
	done; \
	echo "ALL ASAN TEST SUITES PASSED"

$(LIB): $(OBJ_FILES)
	$(AR) rcs $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f $(TEST_BINS) $(INTEROP_BINS) $(TEST_DIR)/gen_cert $(TEST_DIR)/cert_0_0_0_0.der \
	      $(OBJ_FILES) $(LIB) $(FUZZ_BINS) $(TEST_DIR)/asan-*
