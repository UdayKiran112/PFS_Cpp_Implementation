# Compiler and Flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -g -O0 -fno-omit-frame-pointer -I$(SRC_DIR)/Lib -I$(SRC_DIR)

# Directories
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin
LIB_DIR = Lib

# Project Source Files
SRCS = main.cpp Key.cpp TA.cpp Vehicle.cpp Message.cpp
OBJS = $(SRCS:%.cpp=$(OBJ_DIR)/%.o)
LIBS = $(LIB_DIR)/core.a

# Executable
TARGET = $(BIN_DIR)/app

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
all: $(OBJ_DIR) $(BIN_DIR) $(TARGET)

# Link the object files and core.a to create the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

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
	$(DEL_CMD) $(OBJ_DIR)$(SLASH)*.o $(TARGET)

.PHONY: all clean
