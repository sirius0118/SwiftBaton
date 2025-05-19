obj-m := AccessCollector.o 

AccessCollector-y := collect-access.o access-area.o 

.PNONY: all 

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

