EXENAME = Poracle
OBJS1 = Poracle.o
OBJS2 = Poracle.c Poracle.h
CLEAN = rm Poracle.o

LD = gcc
CXX = gcc

all : $(EXENAME)
 
$(EXENAME): $(OBJS1)
	$(LD) -o $(EXENAME) $(OBJS1); $(CLEAN)

Poracle.o: $(OBJS2)
	$(CXX) -g -c Poracle.c


