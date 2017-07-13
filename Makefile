.SUFFIXES : .c .o
 
OBJECT = pcap_test.o
SRC = pcap_test.c
 
CC = gcc
CFLAGS = -lpcap

TARGET = pcap_test
 
$(TARGET) : $(OBJECT)
	@echo "------------------------------------"
	@echo [Complie] pcap_test
	$(CC) -o $(TARGET) $(OBJECT) $(CFLAGS)
	@echo [OK] pcap_test
	@echo "------------------------------------"
	rm -rf $(OBJECT)
 
clean :
	rm -rf $(OBJECT) $(TARGET)

new :
	@$(MAKE) -s clean
	@$(MAKE) -s

pcap_test.o : pcap_test.c net_header.h
