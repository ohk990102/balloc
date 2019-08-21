NM=nm
CFLAGS=-g -Os -fPIC -fno-stack-protector -Wall -Wno-unused-result -U_FORTIFY_SOURCE

.PHONY: clean test_backup test 

define run_test
    @echo "Running $(2) x $(3)"
	@for n in `seq 1 $(3)`; do cat $(2).bin; done | $(1) 2>$(2).out
endef
all: test_backup test 

test: replay
	@echo "[*] Real Test"
	@echo "Imports (Do not use any that are not in whitelist!)"
	@$(NM) -u ./$< | sed -ne 's/\s*U \([^@]*\).*/\t\1/p'
	$(call run_test,./$<,test1,1000)
	$(call run_test,./$<,test2,1000)
	$(call run_test,./$<,test3,20)
	@echo "[+] Real Test Complete"

test_backup: replay_backup
	@echo "[*] Backup Test"
	@echo "Imports (Do not use any that are not in whitelist!)"
	@$(NM) -u ./$< | sed -ne 's/\s*U \([^@]*\).*/\t\1/p'
	$(call run_test,./$<,test1,1000)
	$(call run_test,./$<,test2,1000)
	$(call run_test,./$<,test3,20)
	@echo "[+] Backup Test Complete"

replay: alloc.c main.c printf.c
	$(CC) $(CFLAGS) -o $@ $^

replay_backup: alloc_backup.c main.c printf.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) replay test*.time test*.out
