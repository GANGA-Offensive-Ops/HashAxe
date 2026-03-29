CXX = g++
NVCC = nvcc

# Targeted architecture (sm_86 for RTX 30-series / Ampere)
CUDA_ARCH = -arch=sm_86

# Flags
NVCCFLAGS = -O3 -Xcompiler -fPIC $(CUDA_ARCH) -dc
LDFLAGS = -shared -lcudart

TARGET = libhashaxe_engine.so

# Kernel source locations
KERNEL_DIR = ../../gpu
FAST_KERNEL_DIR = ../../gpu/kernels

# Objects — modular compilation: each .cu → .o
OBJS = engine.o cuda_kernel.o md5.o ntlm.o sha256.o

all: $(TARGET)

# ── Device kernels ────────────────────────────────────────────────────────────

# Primary bcrypt-KDF kernel
cuda_kernel.o: $(KERNEL_DIR)/cuda_kernel.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

# Fast hash kernels
md5.o: $(FAST_KERNEL_DIR)/md5.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

ntlm.o: $(FAST_KERNEL_DIR)/ntlm.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

sha256.o: $(FAST_KERNEL_DIR)/sha256.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

# ── Host orchestration ────────────────────────────────────────────────────────

engine.o: engine.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

# ── Final link ────────────────────────────────────────────────────────────────

$(TARGET): $(OBJS)
	$(NVCC) -shared $(CUDA_ARCH) -o $@ $(OBJS)

clean:
	rm -f *.o $(TARGET)

.PHONY: all clean
