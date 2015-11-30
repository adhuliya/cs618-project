
#------ MAKE CHANGES TO BASE_DIR : Please put the path to base directory of your pristine gcc-4.7.2 build -----------#
#BASE_DIR = /home/codeman/setup/gcc/gcc472/gcc472b/gcc-build
BASE_DIR = /home/codeman/setup/gcc/gcc520/gcc520a
#BASE_DIR=/home/komal/gcc/gcc520
INSTALL = $(BASE_DIR)/install
#INSTALL = $(BASE_DIR)/gcc-install
CPP = $(INSTALL)/bin/g++
CC = $(INSTALL)/bin/gcc
NEW_PATH = $(BASE_DIR)/build/gcc

GCCPLUGINS_DIR:= $(shell $(CPP) -print-file-name=plugin)
#INCLUDE= -I$(GCCPLUGINS_DIR)/include -I$(NEW_PATH)
#INCLUDE= -I$(GCCPLUGINS_DIR)/include 
INCLUDE= -I$(GCCPLUGINS_DIR)/include -I/usr/include/x86_64-linux-gnu

FLAGS= -fPIC -flto -flto-partition=none 
FLAGS1= -fPIC -O3 -fno-rtti

%.o: %.c
	$(CC) $(FLAGS) $(INCLUDE) -c $< 

%.o: %.cpp
	$(CPP) $(FLAGS1) -std=c++0x -O0 $(INCLUDE) -c $< 

plugin.so: block_information.o parser.o analysis_plugin.o
	$(CPP) $(INCLUDE) $(FLAGS1) -O0 -shared $^ -fdump-ipa-all -fdump-tree-all -o $@


TEST_OBJS=test.o
test: $(TEST_OBJS) plugin.so
	$(CPP) -fplugin=./plugin.so $(TEST_OBJS) -flto -flto-partition=none -O3 -fdump-ipa-all -fdump-tree-all -o result

clean:
	\rm -f *.c.* *~ a.out result*
	\rm plugin.so* *.o

