# compiler
CC  = gcc
# compile options
CFLAGS    = -Wall
# library files to link
LIBS    = -lcrypto -lpthread
# name of executable
TARGET  = signer
# target src code
SRCS    = ./src/*
# include directory
INCDIR  = -I ./include
# configuration directory
ETCDIR = ./etc
# artifact directory
OUTDIR	= ./out

# if no target given, go for 'all'
.DEFAULT_GOAL := all

# Print help text
help:
	@echo
	@echo "	all		Cleans and builds the application (default)."
	@echo "	clean		Removes artifacts directories."
	@echo "	$(TARGET)		Builds and outputs to $(OUTDIR) with existing caches."
	@echo "	build		Same as '$(TARGET)' (for convenience)."
	@echo "	help		Display this help."
	@echo

# Reset the output directories
clean:
	-rm -rf $(OUTDIR)

# Build the application
build: $(TARGET)
$(TARGET):
	mkdir -p $(OUTDIR)
	cp -r $(ETCDIR) $(OUTDIR)
	$(CC) $(SRCS) -o $(OUTDIR)/$@ $(INCDIR) $(LIBS) $(CFLAGS)

# Make all
all: clean $(TARGET)
