import os
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import itertools
import time
from eth_hash.auto import keccak
from concurrent.futures import ThreadPoolExecutor
from eth_keys import keys

# Inicializa o gerador de mnemônicos
mnemo = Mnemonic("english")

# Endereço fornecido (normalizado)
target_address = "0x2468e3576D94009F0Bd23795161E55d122d07dB6".lower()

# Lista de palavras conhecidas
known_words = [
    "hand", "couch", "avocado", "insect", "laugh", "table", "yellow",
    "cattle", "peanut", "plate", "phone", "switch"
]

# Nome dos arquivos para salvar os resultados
all_attempts_file = "all_attempts.txt"
key_puzzle_file = "key_puzzle.txt"
tested_combinations_file = "tested_combinations.txt"

# Variável global para contagem de tentativas
attempts = 0

# Buffer para tentativas para reduzir operações de I/O
attempts_buffer = []

# Contador de permutações por minuto
permutations_per_minute = 0

def load_tested_combinations():
    if os.path.exists(tested_combinations_file):
        with open(tested_combinations_file, "r") as f:
            return set(line.strip() for line in f.readlines())
    return set()

def save_tested_combination(mnemonic):
    with open(tested_combinations_file, "a") as f:
        f.write(mnemonic + "\n")

def generate_mnemonic(combination):
    return " ".join(combination)

def generate_address(mnemonic):
    seed = mnemo.to_seed(mnemonic)
    root_key = BIP32Key.fromEntropy(seed)

    # Derivando a chave privada na conta padrão BIP44 (m/44'/60'/0'/0/0)
    child_key = root_key.ChildKey(44 + 0x80000000).ChildKey(60 + 0x80000000).ChildKey(0 + 0x80000000).ChildKey(0).ChildKey(0)
    private_key = keys.PrivateKey(child_key.PrivateKey())

    # Gerar o endereço Ethereum a partir da chave pública
    public_key = private_key.public_key
    address = "0x" + keccak(public_key.to_bytes())[12:].hex()

    return address

def save_attempt(mnemonic, wallet, is_match):
    # Adiciona tentativas ao buffer
    global attempts_buffer
    attempts_buffer.append(f"Mnemonic: {mnemonic}\nAddress: {wallet}\nMatch: {'Yes' if is_match else 'No'}\n\n")

    # Escreve buffer em arquivo periodicamente
    if len(attempts_buffer) >= 100:
        with open(all_attempts_file, "a") as f:
            f.writelines(attempts_buffer)
        attempts_buffer = []

    if is_match:
        with open(key_puzzle_file, "a") as f:
            f.write(f"Mnemonic: {mnemonic}\nAddress: {wallet}\nMatch: Yes\n\n")

def process_combination(combination, tested_combinations):
    global attempts
    global permutations_per_minute
    mnemonic = generate_mnemonic(combination)
    if mnemonic in tested_combinations:
        return

    wallet = generate_address(mnemonic)
    is_match = wallet.lower() == target_address.lower()
    save_attempt(mnemonic, wallet, is_match)
    save_tested_combination(mnemonic)

    # Incrementa a contagem de tentativas
    attempts += 1
    permutations_per_minute += 1

def find_address_for_target(target_address):
    global attempts
    global permutations_per_minute
    tested_combinations = load_tested_combinations()
    start_time = time.time()

    # Fixar a terceira palavra como "avocado"
    fixed_word = known_words[2]
    words_to_permute = known_words[:2] + known_words[3:]

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for combination in itertools.permutations(words_to_permute):
            perm_combination = list(combination[:2]) + [fixed_word] + list(combination[2:])

            mnemonic = generate_mnemonic(perm_combination)

            # Verifica se a combinação já foi testada
            if mnemonic in tested_combinations:
                continue

            futures.append(executor.submit(process_combination, perm_combination, tested_combinations))

            # Imprime o número de tentativas a cada combinação processada
            print(f'Tentativas feitas até agora: {attempts}')
        
        # Monitorar tentativas a cada 60 segundos
        while futures:
            time.sleep(60)  # Espera 60 segundos
            print(f'Tentativas feitas no último minuto: {attempts}')  # Imprime a contagem total
            print(f'Permutações realizadas no último minuto: {permutations_per_minute}')  # Imprime a contagem de permutações por minuto
            permutations_per_minute = 0  # Reseta o contador de permutações
            # Remove completadas
            futures = [f for f in futures if not f.done()]

    # Grava qualquer tentativa restante no buffer
    if attempts_buffer:
        with open(all_attempts_file, "a") as f:
            f.writelines(attempts_buffer)

if __name__ == "__main__":
    print('bip39 private key combinador V1')
    print('Gera uma chave privada para um endereço específico.')
    while True:
        find_address_for_target(target_address)
