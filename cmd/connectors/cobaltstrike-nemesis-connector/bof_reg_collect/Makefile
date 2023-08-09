BOFNAME := reg_collect
INCLUDE := -I ./common
FLAGS=-DBOF -c -Os -Wall
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	mkdir -p ./build/
	$(CC_x64) -o ./build/$(BOFNAME).x64.o $(INCLUDE) $(FLAGS) ./src/entry.c
	$(CC_x86) -o ./build/$(BOFNAME).x86.o $(INCLUDE) $(FLAGS) ./src/entry.c

clean:
	rm $(BOFNAME).*.exe