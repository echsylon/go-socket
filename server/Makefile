#  MIT License
#
#  Copyright (c) 2024 Echsylon Digital Solutions AB
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.

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
