# Define the C++ compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

# Define source files and object files
SRCS = SecureVault.cpp main.cpp
OBJS = $(SRCS:.cpp=.o)

# Define the executable name
TARGET = SecureVaultDemo

# Default target: builds the executable
all: $(TARGET)

# Rule to link object files into the final executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

# Rule to compile C++ source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Run the program
run: $(TARGET)
	./$(TARGET)

# Clean up generated files
clean:
	rm -f $(OBJS) $(TARGET) test_vault.dat

.PHONY: all run clean
