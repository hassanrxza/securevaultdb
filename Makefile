CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2

SRCS = BTree.cpp SecureVault.cpp main.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = SecureVaultHybrid

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) vault.db vault.idx

run: $(TARGET)
	./$(TARGET)
