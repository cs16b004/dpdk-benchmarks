CC=g++
SRC_DIR=./src
OBJ_DIR=./build

LIB_DPDK=$(shell pkg-config --libs libdpdk) -lrte_net_qdma
CFLAG_DPDK=$(shell pkg-config --cflags libdpdk)

EXECUTABLE=server
SRC=$(shell find $(SRC_DIR) -type f -name *.cpp)
OBJ=$(patsubst $(SRC_DIR)/%,$(OBJ_DIR)/%,$(SRC:.cpp=.o))
OBJ_EXE=$(addprefix $(OBJ_DIR)/,$(addsuffix .o,$(EXECUTABLE)))
OBJ_SHARED=$(filter-out $(OBJ_EXE),$(OBJ))
DEP=./deps.hpp

OPT=-O2
NO_OPT=-O0
CFLAGS=-Wall -std=c++17 $(CFLAG_DPDK)
LIBS=-lpthread -lyaml-cpp $(LIB_DPDK)

.PHONY: all
all: release

new: clean $(EXECUTABLE)

debug: CFLAGS += -g3 $(NO_OPT) -DLOG_LEVEL_AS_DEBUG
debug: clean $(EXECUTABLE)

release: CFLAGS += $(OPT)
release: $(EXECUTABLE)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp $(SRC_DIR)/%.hpp $(DEP)
	echo "making Target $@ ....."
	@mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS)
 
$(EXECUTABLE): % : $(OBJ_SHARED) $(OBJ_DIR)/%.o
	$(CC) $^ $(CFLAGS) -o $@ $(LIBS)

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)/*
	rm -rf $(OBJ_DIR)
	rm -rf $(EXECUTABLE)
