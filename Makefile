# Makefile for Mewnomics
# Usage: make (or mingw32-make on Windows)

# Force Windows shell
SHELL := cmd.exe
.SHELLFLAGS := /c

# LLVM/Clang paths
CLANG_PATH := C:\Program Files\LLVM\bin
CC := "$(CLANG_PATH)\clang.exe"
CXX := "$(CLANG_PATH)\clang++.exe"
RC := "$(CLANG_PATH)\llvm-rc.exe"

# Directories
BUILD_DIR := build
MINHOOK_DIR := $(BUILD_DIR)/minhook
INSTALL_DIR := ..

# Compiler flags
CFLAGS := -O2 -I$(MINHOOK_DIR)/include
CXXFLAGS := -std=c++17 -O2 -I$(MINHOOK_DIR)/include -Wno-microsoft-cast -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
LDFLAGS := -static -O2
GUI_LDFLAGS := -Wl,/SUBSYSTEM:WINDOWS -lcomctl32 -lwinhttp -lgdi32 -lshell32 -luser32 -lws2_32 -ladvapi32

# MinHook source files
MINHOOK_SRCS := $(MINHOOK_DIR)/src/buffer.c \
                $(MINHOOK_DIR)/src/hook.c \
                $(MINHOOK_DIR)/src/trampoline.c \
                $(MINHOOK_DIR)/src/hde/hde64.c

MINHOOK_OBJS := $(BUILD_DIR)/buffer.o \
                $(BUILD_DIR)/hook.o \
                $(BUILD_DIR)/trampoline.o \
                $(BUILD_DIR)/hde64.o

# Hook DLL
HOOK_SRC := hook.cpp
HOOK_OBJ := $(BUILD_DIR)/hook_obj.o
HOOK_DLL := $(BUILD_DIR)/hook.dll

# Launcher GUI
LAUNCHER_SRC := launcher_gui.cpp
LAUNCHER_RES := launcher.res
LAUNCHER_EXE := $(BUILD_DIR)/Mewnomics.exe

# Targets
.PHONY: all minhook resources clean

all: $(HOOK_DLL) $(LAUNCHER_EXE)
	@echo ========================================
	@echo SUCCESS! Build complete!
	@echo ========================================
	@echo Built files:
	@echo   $(HOOK_DLL)
	@echo   $(LAUNCHER_EXE)

# Download MinHook if needed
$(MINHOOK_DIR):
	@echo Downloading MinHook...
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@cd $(BUILD_DIR) && git clone --depth 1 https://github.com/TsudaKageyu/minhook.git

# Compile MinHook
$(BUILD_DIR)/buffer.o: $(MINHOOK_DIR)/src/buffer.c | $(MINHOOK_DIR)
	@echo [MinHook] Compiling buffer.c...
	@$(CC) -c $< -o $@ $(CFLAGS)

$(BUILD_DIR)/hook.o: $(MINHOOK_DIR)/src/hook.c | $(MINHOOK_DIR)
	@echo [MinHook] Compiling hook.c...
	@$(CC) -c $< -o $@ $(CFLAGS)

$(BUILD_DIR)/trampoline.o: $(MINHOOK_DIR)/src/trampoline.c | $(MINHOOK_DIR)
	@echo [MinHook] Compiling trampoline.c...
	@$(CC) -c $< -o $@ $(CFLAGS)

$(BUILD_DIR)/hde64.o: $(MINHOOK_DIR)/src/hde/hde64.c | $(MINHOOK_DIR)
	@echo [MinHook] Compiling hde64.c...
	@$(CC) -c $< -o $@ $(CFLAGS)

# Compile hook.cpp
$(HOOK_OBJ): $(HOOK_SRC) | $(MINHOOK_DIR)
	@echo Compiling hook.cpp...
	@$(CXX) -c $< -o $@ $(CXXFLAGS)

# Link hook.dll
$(HOOK_DLL): $(HOOK_OBJ) $(MINHOOK_OBJS)
	@echo Linking hook.dll...
	@$(CXX) -shared -o $@ $^ -lkernel32 $(LDFLAGS)

# Compile resources
$(LAUNCHER_RES): launcher.rc mewgenics_icon.ico
	@echo Compiling resources...
	@$(RC) /FO $@ $<

# Compile and link launcher
$(LAUNCHER_EXE): $(LAUNCHER_SRC) $(LAUNCHER_RES)
	@echo Compiling Mewnomics.exe...
	@$(CXX) $^ -o $@ $(CXXFLAGS) $(LDFLAGS) $(GUI_LDFLAGS)

# Clean build artifacts
clean:
	@echo Cleaning build artifacts...
	@if exist $(BUILD_DIR)\*.o del /Q $(BUILD_DIR)\*.o
	@if exist $(BUILD_DIR)\*.dll del /Q $(BUILD_DIR)\*.dll
	@if exist $(BUILD_DIR)\*.exe del /Q $(BUILD_DIR)\*.exe
	@if exist $(LAUNCHER_RES) del /Q $(LAUNCHER_RES)
	@echo Clean complete.

# Clean everything including MinHook
distclean: clean
	@echo Removing MinHook...
	@if exist $(MINHOOK_DIR) rmdir /S /Q $(MINHOOK_DIR)
	@echo Distclean complete.
