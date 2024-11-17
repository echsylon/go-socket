# compiler
CC  = go build
# name of executable
TARGET  = client
# target src code
SRCS    = ./src/*
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
	$(CC) -o $(OUTDIR)/$@ $(SRCS)

# Make all
all: clean $(TARGET)
