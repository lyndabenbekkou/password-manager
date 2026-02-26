CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -pedantic -g
LDFLAGS = -lssl -lcrypto -lsqlite3

# Mode debug (ajouter -DDEBUG pour activer les prints de debug)
# CFLAGS += -DDEBUG

# Répertoires
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = .
TEST_DIR = test
COV_DIR = coverage


# Fichiers
TARGET = $(BIN_DIR)/password_manager
SOURCES = main.c crypto.c auth.c database.c
OBJECTS = $(SOURCES:%.c=$(OBJ_DIR)/%.o)
HEADERS = common.h config.h crypto.h auth.h database.h interface.h
TEST_UNIT_SRC = $(TEST_DIR)/test_unitaire.c
TEST_INT_SRC = $(TEST_DIR)/test_integration.c

# Exécutables de test
TEST_UNIT_TARGET = $(BIN_DIR)/test_unitaire
TEST_INT_TARGET = $(BIN_DIR)/test_integration

# Objets nécessaires pour les tests
TEST_OBJECTS = $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS))


# Règles principales
.PHONY: all clean run help test test_unit test_int

all: $(TARGET)


$(TARGET): $(OBJECTS)
	@echo "🔗 Linking $(TARGET)..."
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "✅ Build successful!"
	@echo "   Run with: ./password_manager"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(OBJ_DIR)
	@echo "🔨 Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@


$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

# TESTS

$(TEST_UNIT_TARGET): $(TEST_UNIT_SRC) $(TEST_OBJECTS)
	@echo "🔨 Compiling Unit Tests (with coverage)..."
	$(CC) $(CFLAGS) -I. $(TEST_UNIT_SRC) \
		crypto.c auth.c database.c -o $(TEST_UNIT_TARGET) $(LDFLAGS)


$(TEST_INT_TARGET): $(TEST_INT_SRC) $(TEST_OBJECTS)
	@echo "🔨 Compiling Integration Tests (with coverage)..."
	$(CC) $(CFLAGS) -I. $(TEST_INT_SRC) \
		crypto.c auth.c database.c -o $(TEST_INT_TARGET) $(LDFLAGS)


test: $(TEST_UNIT_TARGET) $(TEST_INT_TARGET)
	@echo ""
	@echo "RUNNING UNIT TESTS AND INTEGRATION TESTS"
	@./$(TEST_UNIT_TARGET) 2>/dev/null || (echo "❌ Unit Tests Failed" && exit 1)
	@echo "✅ Unit Tests Passed"
	@echo ""
	@./$(TEST_INT_TARGET) 2>/dev/null
	@echo "✅ Integration Tests Passed" || (echo "❌ Integration Tests Failed" && exit 1)
	@echo ""
	@echo "🎉 ALL TESTS PASSED!"


test_unit: $(TEST_UNIT_TARGET)
	@./$(TEST_UNIT_TARGET)
	@echo ""

test_int: $(TEST_INT_TARGET)
	@./$(TEST_INT_TARGET)
	@echo ""



clean:
	@echo "🧹 Cleaning build files..."
	rm -rf $(OBJ_DIR)
	rm -f $(TARGET)
	rm -f $(TEST_UNIT_TARGET) $(TEST_INT_TARGET)
	rm -f password_manager.db test_suite.db test_integration.db *.gcda *.gcno *.gcov
	@echo "✨ Clean complete!"


run: $(TARGET)
	@echo "🚀 Running password manager..."
	@echo ""
	./$(TARGET)

# Aide
help:
	@echo "📖 Password Manager - Makefile Help"
	@echo ""
	@echo "Available targets:"
	@echo "  make              - Compile le projet"
	@echo "  make all          - Compile le projet"
	@echo "  make clean        - Nettoie les fichiers compilés"
	@echo "  make run          - Compile et exécute"
	@echo "  make help     	   - Affiche cette aide"
	@echo "  make test         - Lance tous les tests"
	@echo "  make test_unit    - Lance uniquement les tests unitaires"
	@echo "  make test_int     - Lance uniquement les tests d'intégration"
	@echo ""
	@echo "Debug mode:"
	@echo "  make CFLAGS+='-DDEBUG' - Compile avec debug prints"
	@echo ""
	@echo "Dependencies:"
	@echo "  - OpenSSL (libssl-dev)"
	@echo "  - SQLite3 (libsqlite3-dev)"


.PHONY: check valgrind
