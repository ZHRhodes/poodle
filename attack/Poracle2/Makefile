EXENAME = Poracle2
OBJS1 = Poracle2.o
OBJS2 = Poracle2.c Poracle2.h
CLEAN = rm Poracle2.o

LD = gcc
CXX = gcc

all : $(EXENAME)
 
$(EXENAME): $(OBJS1)
	$(LD) -o $(EXENAME) $(OBJS1); $(CLEAN)

Poracle2.o: $(OBJS2)
	$(CXX) -g -c Poracle2.c


