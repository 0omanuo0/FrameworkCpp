CXX = g++
CXXFLAGS_COMMON = -Isrc 
# ssl, crypto, sqlite3, curl
LDFLAGS = -lssl -lcrypto -lsqlite3 -lcurl

SRC_DIR = src
BIN_DIR = bin

SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BIN_DIR)/%.o,$(SRCS))

DEBUG_CXXFLAGS = -Wall -g -Og -fdiagnostics-color=always
RELEASE_CXXFLAGS = -O3

EXECUTABLE = $(BIN_DIR)/httpserver.out

all: debug

debug: CXXFLAGS = $(DEBUG_CXXFLAGS) $(CXXFLAGS_COMMON)
debug: $(BIN_DIR) $(EXECUTABLE)

release: CXXFLAGS = $(RELEASE_CXXFLAGS) $(CXXFLAGS_COMMON)
release: $(BIN_DIR) $(EXECUTABLE)

# Create the bin directory if it doesn't exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Use the -j option to enable parallel compilation (e.g., make -j4)
$(OBJS): $(BIN_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJS) app.cpp
	$(CXX) $(CXXFLAGS) $(OBJS) app.cpp -o $(EXECUTABLE) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(EXECUTABLE)

.PHONY: all debug release clean
