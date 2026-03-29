#include <cuda_runtime.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <stdint.h>

extern "C" {
    // Native context manager for the CUDA pinned-memory batch engine.
    
    struct EngineContext {
        int gpu_id;
        cudaStream_t stream0;
        cudaStream_t stream1;
        
        // Pinned memory buffers
        uint8_t* h_pw_flat_0;
        int* h_pw_lens_0;
        uint8_t* h_results_0;
        
        uint8_t* h_pw_flat_1;
        int* h_pw_lens_1;
        uint8_t* h_results_1;
        
        // Device memory buffers
        uint8_t* d_pw_flat_0;
        int* d_pw_lens_0;
        uint8_t* d_results_0;
        
        uint8_t* d_pw_flat_1;
        int* d_pw_lens_1;
        uint8_t* d_results_1;

        uint8_t* d_salt;
        uint8_t* d_edata;
        
        int max_batch_size;
        int max_pw_len;
    };

    void* engine_init(int gpu_id, int max_batch_size, int max_pw_len) {
        // Set device
        if (cudaSetDevice(gpu_id) != cudaSuccess) return nullptr;
        
        EngineContext* ctx = new EngineContext();
        ctx->gpu_id = gpu_id;
        ctx->max_batch_size = max_batch_size;
        ctx->max_pw_len = max_pw_len;
        
        cudaStreamCreate(&ctx->stream0);
        cudaStreamCreate(&ctx->stream1);
        
        size_t pw_bytes = max_batch_size * max_pw_len;
        size_t lens_bytes = max_batch_size * sizeof(int);
        size_t res_bytes = max_batch_size;
        
        // Allocate pinned host memory
        cudaHostAlloc((void**)&ctx->h_pw_flat_0, pw_bytes, cudaHostAllocDefault);
        cudaHostAlloc((void**)&ctx->h_pw_lens_0, lens_bytes, cudaHostAllocDefault);
        cudaHostAlloc((void**)&ctx->h_results_0, res_bytes, cudaHostAllocDefault);
        
        cudaHostAlloc((void**)&ctx->h_pw_flat_1, pw_bytes, cudaHostAllocDefault);
        cudaHostAlloc((void**)&ctx->h_pw_lens_1, lens_bytes, cudaHostAllocDefault);
        cudaHostAlloc((void**)&ctx->h_results_1, res_bytes, cudaHostAllocDefault);
        
        // Allocate device memory
        cudaMalloc(&ctx->d_pw_flat_0, pw_bytes);
        cudaMalloc(&ctx->d_pw_lens_0, lens_bytes);
        cudaMalloc(&ctx->d_results_0, res_bytes);
        
        cudaMalloc(&ctx->d_pw_flat_1, pw_bytes);
        cudaMalloc(&ctx->d_pw_lens_1, lens_bytes);
        cudaMalloc(&ctx->d_results_1, res_bytes);
        
        cudaMalloc(&ctx->d_salt, 16);  // Max salt len config
        cudaMalloc(&ctx->d_edata, 16); // Magic bytes checker
        
        return ctx;
    }
    
    void engine_destroy(void* handle) {
        if (!handle) return;
        EngineContext* ctx = (EngineContext*)handle;
        
        cudaFreeHost(ctx->h_pw_flat_0);
        cudaFreeHost(ctx->h_pw_lens_0);
        cudaFreeHost(ctx->h_results_0);
        
        cudaFreeHost(ctx->h_pw_flat_1);
        cudaFreeHost(ctx->h_pw_lens_1);
        cudaFreeHost(ctx->h_results_1);
        
        cudaFree(ctx->d_pw_flat_0);
        cudaFree(ctx->d_pw_lens_0);
        cudaFree(ctx->d_results_0);
        
        cudaFree(ctx->d_pw_flat_1);
        cudaFree(ctx->d_pw_lens_1);
        cudaFree(ctx->d_results_1);
        
        cudaFree(ctx->d_salt);
        cudaFree(ctx->d_edata);
        
        cudaStreamDestroy(ctx->stream0);
        cudaStreamDestroy(ctx->stream1);
        
        delete ctx;
    }

    uint8_t* engine_get_pw_flat(void* handle, int buf_idx) {
        EngineContext* ctx = (EngineContext*)handle;
        return buf_idx == 0 ? ctx->h_pw_flat_0 : ctx->h_pw_flat_1;
    }
    
    int* engine_get_pw_lens(void* handle, int buf_idx) {
        EngineContext* ctx = (EngineContext*)handle;
        return buf_idx == 0 ? ctx->h_pw_lens_0 : ctx->h_pw_lens_1;
    }

    uint8_t* engine_get_results(void* handle, int buf_idx) {
        EngineContext* ctx = (EngineContext*)handle;
        return buf_idx == 0 ? ctx->h_results_0 : ctx->h_results_1;
    }

    // End of getters
}

// Do not include cuda_kernel.cu directly. It will be linked as a separate object file.
extern "C" __global__ void hashaxe_bcrypt_ssh(
    const uint8_t  *passwords,
    const int      *pw_lengths,
    int             max_pw_len,
    int             n_passwords,
    const uint8_t  *salt,
    int             salt_len,
    int             rounds,
    int             key_len,
    int             iv_len,
    const uint8_t  *edata,
    int             cipher_id,
    uint8_t        *results
);

extern "C" {
    void engine_launch(void* handle, int buf_idx, int n_passwords,
                      const uint8_t* salt, int salt_len, int rounds,
                      int key_len, int iv_len,
                      const uint8_t* edata, int edata_len) 
    {
        EngineContext* ctx = (EngineContext*)handle;
        cudaStream_t stream = buf_idx == 0 ? ctx->stream0 : ctx->stream1;
        
        uint8_t* d_pw_flat = buf_idx == 0 ? ctx->d_pw_flat_0 : ctx->d_pw_flat_1;
        int* d_pw_lens = buf_idx == 0 ? ctx->d_pw_lens_0 : ctx->d_pw_lens_1;
        uint8_t* d_results = buf_idx == 0 ? ctx->d_results_0 : ctx->d_results_1;
        
        uint8_t* h_pw_flat = buf_idx == 0 ? ctx->h_pw_flat_0 : ctx->h_pw_flat_1;
        int* h_pw_lens = buf_idx == 0 ? ctx->h_pw_lens_0 : ctx->h_pw_lens_1;
        uint8_t* h_results = buf_idx == 0 ? ctx->h_results_0 : ctx->h_results_1;

        size_t pw_bytes = n_passwords * ctx->max_pw_len;
        size_t lens_bytes = n_passwords * sizeof(int);
        size_t res_bytes = n_passwords;

        // Reset results to 0 on host memory before copying so old matches aren't re-used
        memset(h_results, 0, res_bytes);

        // Copy up to device
        cudaMemcpyAsync(d_pw_flat, h_pw_flat, pw_bytes, cudaMemcpyHostToDevice, stream);
        cudaMemcpyAsync(d_pw_lens, h_pw_lens, lens_bytes, cudaMemcpyHostToDevice, stream);
        cudaMemcpyAsync(ctx->d_salt, salt, salt_len, cudaMemcpyHostToDevice, stream);
        cudaMemcpyAsync(ctx->d_edata, edata, edata_len, cudaMemcpyHostToDevice, stream);
        cudaMemcpyAsync(d_results, h_results, res_bytes, cudaMemcpyHostToDevice, stream);

        int block = 256;
        int grid = (n_passwords + block - 1) / block;

        // Launch kernel
        hashaxe_bcrypt_ssh<<<grid, block, 0, stream>>>(
            d_pw_flat, d_pw_lens, ctx->max_pw_len, n_passwords,
            ctx->d_salt, salt_len, rounds,
            key_len, iv_len,
            ctx->d_edata, 0,
            d_results
        );

        // Copy down results
        cudaMemcpyAsync(h_results, d_results, res_bytes, cudaMemcpyDeviceToHost, stream);
    }

    void engine_sync(void* handle, int buf_idx) {
        EngineContext* ctx = (EngineContext*)handle;
        cudaStream_t stream = buf_idx == 0 ? ctx->stream0 : ctx->stream1;
        cudaStreamSynchronize(stream);
    }
}

// ── Fast Hash Kernel Extern Declarations ─────────────────────────────────────
// These kernels are compiled from separate .cu object files and linked in.

__global__ void md5_hashaxeKernel(
    const uint8_t* candidates, const int* lengths,
    int num_candidates, const uint32_t* target_hash, int* d_found_idx
);

__global__ void ntlm_hashaxeKernel(
    const uint8_t* candidates, const int* lengths,
    int num_candidates, const uint32_t* target_hash, int* d_found_idx
);

__global__ void sha256_hashaxeKernel(
    const uint8_t* candidates, const int* lengths,
    int num_candidates, const uint32_t* target_hash, int* d_found_idx
);

// ── Fast Hash C API ──────────────────────────────────────────────────────────
// These functions are called from Python via ctypes.
// They handle all GPU memory allocation/deallocation internally.

extern "C" {

    int engine_fast_hash_hashaxe(
        int hash_type,                  // 0=MD5, 1=NTLM, 2=SHA256
        const uint8_t* h_candidates,    // flat array: num * 64 bytes
        const int* h_lengths,           // array of lengths
        int num_candidates,
        const uint8_t* h_target_hash,   // 16 bytes (MD5/NTLM) or 32 bytes (SHA256)
        int target_hash_bytes
    ) {
        // Device pointers
        uint8_t* d_candidates = nullptr;
        int* d_lengths = nullptr;
        uint32_t* d_target = nullptr;
        int* d_found = nullptr;

        size_t cand_bytes = (size_t)num_candidates * 64;
        size_t lens_bytes = (size_t)num_candidates * sizeof(int);

        cudaMalloc(&d_candidates, cand_bytes);
        cudaMalloc(&d_lengths, lens_bytes);
        cudaMalloc(&d_target, target_hash_bytes);
        cudaMalloc(&d_found, sizeof(int));

        cudaMemcpy(d_candidates, h_candidates, cand_bytes, cudaMemcpyHostToDevice);
        cudaMemcpy(d_lengths, h_lengths, lens_bytes, cudaMemcpyHostToDevice);
        cudaMemcpy(d_target, h_target_hash, target_hash_bytes, cudaMemcpyHostToDevice);

        int h_found = -1;
        cudaMemcpy(d_found, &h_found, sizeof(int), cudaMemcpyHostToDevice);

        int block = 256;
        int grid = (num_candidates + block - 1) / block;

        switch (hash_type) {
            case 0: // MD5
                md5_hashaxeKernel<<<grid, block>>>(
                    d_candidates, d_lengths, num_candidates, d_target, d_found);
                break;
            case 1: // NTLM
                ntlm_hashaxeKernel<<<grid, block>>>(
                    d_candidates, d_lengths, num_candidates, d_target, d_found);
                break;
            case 2: // SHA256
                sha256_hashaxeKernel<<<grid, block>>>(
                    d_candidates, d_lengths, num_candidates, d_target, d_found);
                break;
            default:
                cudaFree(d_candidates);
                cudaFree(d_lengths);
                cudaFree(d_target);
                cudaFree(d_found);
                return -2; // Unsupported hash type
        }

        cudaDeviceSynchronize();
        cudaMemcpy(&h_found, d_found, sizeof(int), cudaMemcpyDeviceToHost);

        cudaFree(d_candidates);
        cudaFree(d_lengths);
        cudaFree(d_target);
        cudaFree(d_found);

        return h_found; // -1 = not found, >= 0 = index of match
    }

}
