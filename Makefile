.SUFFIXES : .c .o
 
OBJECT = main.o pcap_test.o
SRC = main.c pcap_test.c
 
CC = gcc
CFLAGS = -lpcap -Wall

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

main.o : main.c net_header.h
pcap_test.o : pcap_test.c net_header.h
