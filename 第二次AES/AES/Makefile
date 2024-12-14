# BUILD_DIR = build
# INC_DIR = inc
# SRC_DIR = src

# all:
# 	gcc \
# 		-Wall -Wextra           \
# 		-O3 -funroll-loops      \
# 		-march=native			\
# 		-I$(INC_DIR)			\
# 		$(SRC_DIR)/*.c		    \
# 		-o $(BUILD_DIR)/aes 

# clean:
# 	rm -f $(BUILD_DIR)/*
# 定义变量
BUILD_DIR = build
INC_DIR = inc
SRC_DIR = src

# 编译器和编译选项
CC = gcc
CFLAGS = -Wall -Wextra -O3 -funroll-loops -march=native -I$(INC_DIR)

# 最终生成的目标文件
TARGET = $(BUILD_DIR)/aes
SRCS = $(wildcard $(SRC_DIR)/*.c)

# 默认目标
all: $(BUILD_DIR) $(TARGET)

# 确保 build 目录存在
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# 生成目标文件
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@

# 清理目标
clean:
	rm -f $(BUILD_DIR)/*
