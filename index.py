import os
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import itertools
import time
from eth_hash.auto import keccak
from concurrent.futures import ProcessPoolExecutor, as_completed
from eth_keys import keys
from multiprocessing import Manager

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
all_attempts_file = "all_attempts.txt"
key_puzzle_file = "key_puzzle.txt"
tested_combinations_file = "tested_combinations.txt"

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

def process_combination(combination, tested_combinations, attempts, attempts_lock):
    mnemonic = generate_mnemonic(combination)
    if mnemonic in tested_combinations:
        return False

    wallet = generate_address(mnemonic)
    is_match = wallet.lower() == target_address.lower()

    # Atualiza o contador de tentativas
    with attempts_lock:
        attempts.value += 1

    if is_match:
        print(f"Endereço encontrado! Mnemonic: {mnemonic}")
        return True

    # Salva a combinação testada
    save_tested_combination(mnemonic)
    return False

def find_address_for_target(target_address):
    tested_combinations = load_tested_combinations()
    start_time = time.time()

    # Fixar a terceira palavra como "avocado"
    fixed_word = known_words[2]
    words_to_permute = known_words[:2] + known_words[3:]

    # Usar Manager para compartilhar o contador de tentativas entre processos
    with Manager() as manager:
        attempts = manager.Value('i', 0)  # Contador de tentativas
        attempts_lock = manager.Lock()    # Lock para evitar condições de corrida

        with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = []
            for combination in itertools.permutations(words_to_permute):
                perm_combination = list(combination[:2]) + [fixed_word] + list(combination[2:])
                futures.append(executor.submit(process_combination, perm_combination, tested_combinations, attempts, attempts_lock))

                # Monitorar tentativas a cada 100 combinações
                if len(futures) % 100 == 0:
                    elapsed_time = time.time() - start_time
                    combinations_per_minute = (attempts.value / elapsed_time) * 60
                    print(f"Combinações realizadas: {attempts.value} | Taxa: {combinations_per_minute:.2f} combinações/minuto")

            for future in as_completed(futures):
                if future.result():
                    print("Endereço encontrado!")
                    return

if __name__ == "__main__":
    print('bip39 private key combinador V1')
    print('Gera uma chave privada para um endereço específico.')
    while True:
        find_address_for_target(target_address)