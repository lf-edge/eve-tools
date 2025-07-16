# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

APP_NAME := vcomlink-server
PKG := ./$(SRC_DIR)/...
SRC_DIR := src/
BIN_DIR := bin
OUTPUT_BIN := $(BIN_DIR)/$(APP_NAME)

.PHONY: all
all: build

.PHONY: build
build: fmt lint
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(OUTPUT_BIN) ./$(SRC_DIR)

.PHONY: run
run: build
	@echo "Running $(APP_NAME)..."
	@./$(BIN_DIR)/$(APP_NAME)

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt $(PKG)

.PHONY: lint
lint:
	@echo "Running go vet..."
	@go vet $(PKG)

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
