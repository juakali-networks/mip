IDIR =../include


CC=gcc
CFLAGS=-I$(IDIR)

# rdisc server (-r option) support [no|yes]
#ENABLE_RDISC_SERVER=yes

ODIR=obj
LDIR =../lib

# LIBS=-lm

_DEPS = mip.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = mip.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -DRDISC_SERVER -c -o $@ $< $(CFLAGS)

mip: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
      


.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
