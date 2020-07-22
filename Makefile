INCS-libpcap = -I/usr/include/ -I/usr/local/include/ -I./inc/
LIBS-libpcap = -L/usr/lib/ -L/usr/local/lib/ -L./lib/ -lpcap -lpfring
CFLAG = -std=gnu99
CPPFLASG = -std=c++11

none:
	@echo "\ndo nothing with no target"
	@echo "please input the format of \"make target\""
	@echo "input \"make help\" to understand the detailed information of targets\n"





help:
	@echo "\nthis is make help\n"
	
	@echo "cleaning targets"
	@echo "clean:			rm *.o files"
	@echo "distclean:		rm *.o *.exe files\n"
	
	@echo "compiling targets"
	@echo "demo: 	compile demo\n"



demo: start cap_packet_pfring.o
	gcc ./bin/cap_packet_pfring.o -o ./bin/cap_packet_pfring $(LIBS-libpcap)
	@echo "\033[31m\n\n\tcompile successfully!\n\n\033[0m"

start:
	@echo "\033[32m\n\n\tstart compile!\n\n\033[33m"

cap_packet_pfring.o: ./src/cap_packet_pfring.c
	gcc -c -g $(CFLAG) $(INCS-libpcap) $(LIBS-libpcap) ./src/cap_packet_pfring.c -o ./bin/cap_packet_pfring.o
	@echo


install:
	cp ./bin/cap_packet_pfring /usr/local/bin/


clean:
	rm -rf ./bin/*.o
	rm -rf ./output/log/*

distclean:
	rm -rf ./bin/*
	rm -rf ./output/log/*

