# Compiler and Flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -fsanitize=address -g -O0 -fno-omit-frame-pointer -I$(SRC_DIR)/Lib -I$(SRC_DIR)

# Directories
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin
LIB_DIR = Lib

# Project Source Files
MAIN_SRCS = main.cpp Key.cpp TA.cpp Vehicle.cpp Message.cpp
PERF_SRCS = timing.cpp Key.cpp TA.cpp Vehicle.cpp Message.cpp
AGG_SRCS = AggregateSignatures.cpp Key.cpp TA.cpp Vehicle.cpp Message.cpp
MAIN_OBJS = $(MAIN_SRCS:%.cpp=$(OBJ_DIR)/%.o)
PERF_OBJS = $(PERF_SRCS:%.cpp=$(OBJ_DIR)/%.o)
AGG_OBJS = $(AGG_SRCS:%.cpp=$(OBJ_DIR)/%.o)
LIBS = $(LIB_DIR)/core.a

# Executables
MAIN_TARGET = $(BIN_DIR)/app
PERF_TARGET = $(BIN_DIR)/timing
AGG_TARGET = $(BIN_DIR)/aggregate

# Detect Operating System
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
else
    DETECTED_OS := $(shell uname -s)
endif

# Adjust paths and commands based on OS
ifeq ($(DETECTED_OS),Windows)
    TARGET = $(BIN_DIR)\app.exe
    DEL_CMD = del /Q
    MKDIR_CMD = if not exist $(subst /,\,$(1)) mkdir $(subst /,\,$(1))
    SLASH := \\
else
    TARGET = $(BIN_DIR)/app
    DEL_CMD = rm -f
    MKDIR_CMD = mkdir -p $(1)
    SLASH := /
endif

# Rules
all: $(OBJ_DIR) $(BIN_DIR) $(MAIN_TARGET) $(PERF_TARGET) $(AGG_TARGET)

# Separate linking rules for each executable
$(MAIN_TARGET): $(MAIN_OBJS)
	$(CXX) $(CXXFLAGS) -o $(MAIN_TARGET) $(MAIN_OBJS) $(LIBS)

$(PERF_TARGET): $(PERF_OBJS)
	$(CXX) $(CXXFLAGS) -o $(PERF_TARGET) $(PERF_OBJS) $(LIBS)

$(AGG_TARGET): $(AGG_OBJS)
	$(CXX) $(CXXFLAGS) -o $(AGG_TARGET) $(AGG_OBJS) $(LIBS)

# Compile the source files into object files and place them in the OBJ_DIR
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@$(call MKDIR_CMD,$(dir $@))
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create the object and binary directories if they don't exist
$(OBJ_DIR):
	$(call MKDIR_CMD,$(OBJ_DIR))

$(BIN_DIR):
	$(call MKDIR_CMD,$(BIN_DIR))

# Clean up object files and the executable
clean:
	$(DEL_CMD) $(OBJ_DIR)$(SLASH)*.o $(MAIN_TARGET) $(PERF_TARGET) $(AGG_TARGET)

.PHONY: all clean
