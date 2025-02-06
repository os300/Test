import os
import time
import itertools
import pyopencl as cl
from mnemonic import Mnemonic
from eth_hash.auto import keccak
from eth_keys import keys

# Inicializa o gerador de mnemônicos
mnemo = Mnemonic("english")

# Endereço fornecido (normalizado)
target_address = "0x2468e3576D94009F0Bd23795161E55d122d07dB6".lower()

# Lista de palavras conhecidas
known_words = [
    "hand", "couch", "avocado", "insect", "laugh", "table", "eye",
    "cattle", "peanut", "plate", "phone", "switch"
]

# Nome dos arquivos para salvar os resultados
tested_combinations_file = "tested_combinations.txt"

# Inicializa o contexto OpenCL
ctx = cl.create_some_context()
queue = cl.CommandQueue(ctx)

# Kernel OpenCL para gerar endereços Ethereum
kernel_code = """
__kernel void generate_addresses(__global const char* mnemonics, __global char* addresses, int num_mnemonics, int mnemonic_length) {
    int idx = get_global_id(0);
    if (idx < num_mnemonics) {
        // Gera o endereço Ethereum (simplificado para exemplo)
        for (int i = 0; i < 42; i++) {
            addresses[idx * 42 + i] = mnemonics[idx * mnemonic_length + i % mnemonic_length];
        }
    }
}
"""
prg = cl.Program(ctx, kernel_code).build()

def generate_mnemonic(combination):
    return " ".join(combination)

def generate_address_opencl(mnemonics):
    # Prepara os dados para a GPU
    mnemonic_length = max(len(m) for m in mnemonics)
    mnemonics_flat = "".join(m.ljust(mnemonic_length) for m in mnemonics).encode('utf-8')
    addresses_flat = bytearray(len(mnemonics) * 42)

    # Buffers OpenCL
    mf = cl.mem_flags
    mnemonics_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=mnemonics_flat)
    addresses_buf = cl.Buffer(ctx, mf.WRITE_ONLY, len(addresses_flat))

    # Executa o kernel
    prg.generate_addresses(queue, (len(mnemonics),), None, mnemonics_buf, addresses_buf, np.int32(len(mnemonics)), np.int32(mnemonic_length))
    cl.enqueue_copy(queue, addresses_flat, addresses_buf)

    # Converte os endereços gerados para strings
    addresses = [addresses_flat[i * 42:(i + 1) * 42].decode('utf-8').strip() for i in range(len(mnemonics))]
    return addresses

def find_address_for_target(target_address):
    # Fixar a terceira palavra como "avocado"
    fixed_word = known_words[2]
    words_to_permute = known_words[:2] + known_words[3:]

    # Gerar combinações
    combinations = list(itertools.permutations(words_to_permute, len(words_to_permute)))
    mnemonics = [generate_mnemonic(list(combination[:2]) + [fixed_word] + list(combination[2:])) for combination in combinations]

    # Gerar endereços na GPU
    addresses = generate_address_opencl(mnemonics)

    # Verificar correspondência
    for mnemonic, address in zip(mnemonics, addresses):
        if address.lower() == target_address.lower():
            print(f"Endereço encontrado! Mnemonic: {mnemonic}")
            return

    print("Endereço não encontrado.")

if __name__ == "__main__":
    print('bip39 private key combinador V1')
    print('Gera uma chave privada para um endereço específico.')
    find_address_for_target(target_address)