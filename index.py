import os
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import itertools
import time
from eth_hash.auto import keccak
from concurrent.futures import ProcessPoolExecutor, as_completed
from eth_keys import keys
from multiprocessing import Manager, cpu_count
import json

# Inicializa o gerador de mnemônicos
mnemo = Mnemonic("english")

# Endereço fornecido (normalizado)
target_address = "0x2468e3576D94009F0Bd23795161E55d122d07dB6".lower()

# Lista de palavras conhecidas
known_words = [
    "hand", "couch", "avocado", "insect", "laugh", "table", "eye",
    "cattle", "peanut", "plate", "phone", "switch"
]

# Nome do arquivo para salvar as combinações testadas
tested_combinations_file = "tested_combinations.txt"

# Nome do arquivo para salvar todas as combinações da seed phase
all_combinations_file = "all_seed_phase_combinations.json"

# Pasta para salvar o vencedor
vencedor_pasta = "VENCEDOR"

def load_tested_combinations():
    """Carrega as combinações já testadas de um arquivo."""
    try:
        with open(tested_combinations_file, "r") as f:
            return set(line.strip() for line in f.readlines())
    except FileNotFoundError:
        return set()

def save_tested_combination(mnemonic):
    """Salva uma combinação testada no arquivo de cache."""
    with open(tested_combinations_file, "a") as f:
        f.write(mnemonic + "\n")

def generate_mnemonic(combination):
    """Gera uma frase mnemônica a partir de uma combinação de palavras."""
    return " ".join(combination)

def generate_address(mnemonic):
    """Gera um endereço Ethereum a partir de uma frase mnemônica."""
    seed = mnemo.to_seed(mnemonic)
    root_key = BIP32Key.fromEntropy(seed)

    # Derivando a chave privada na conta padrão BIP44 (m/44'/60'/0'/0/0)
    child_key = root_key.ChildKey(44 + 0x80000000).ChildKey(60 + 0x80000000).ChildKey(0 + 0x80000000).ChildKey(0).ChildKey(0)
    private_key = keys.PrivateKey(child_key.PrivateKey())

    # Gerar o endereço Ethereum a partir da chave pública
    public_key = private_key.public_key
    address = "0x" + keccak(public_key.to_bytes())[12:].hex()

    return address

def process_combination(combination, tested_combinations, attempts, attempts_lock, all_combinations):
    """Processa uma combinação de palavras e verifica se corresponde ao endereço alvo."""
    mnemonic = generate_mnemonic(combination)
    if mnemonic in tested_combinations:
        return False

    wallet = generate_address(mnemonic)
    is_match = wallet.lower() == target_address.lower()

    # Atualiza o contador de tentativas
    with attempts_lock:
        attempts.value += 1

    # Salva todas as combinações e seus endereços
    all_combinations[mnemonic] = wallet

    if is_match:
        print(f"Endereço encontrado! Mnemonic: {mnemonic}")
        return mnemonic  # Retorna o mnemonic se encontrar o endereço

    # Salva a combinação testada no cache
    save_tested_combination(mnemonic)
    return False

def generate_combinations():
    """Gera TODAS as combinações de palavras possíveis, mantendo 'avocado' na 3ª posição."""
    fixed_word = known_words[2]  # "avocado"
    other_words = known_words[:2] + known_words[3:]  # Todas as palavras exceto "avocado"

    for combination in itertools.permutations(other_words):
        yield list(combination[:2]) + [fixed_word] + list(combination[2:])


def find_address_for_target(target_address):
    """Procura o endereço alvo a partir de combinações de palavras."""
    tested_combinations = load_tested_combinations()
    start_time = time.time()

    # Usar Manager para compartilhar o contador de tentativas e o dicionário de combinações
    with Manager() as manager:
        attempts = manager.Value('i', 0)  # Contador de tentativas
        attempts_lock = manager.Lock()    # Lock para evitar condições de corrida
        all_combinations = manager.dict() # Dicionário para armazenar todas as combinações

        with ProcessPoolExecutor(max_workers=cpu_count()) as executor:
            combination_generator = generate_combinations()

            while True:  # Loop infinito
                futures = []
                # Processar combinações em lotes
                for _ in range(10500):  # Limite de 10.500 combinações por execução
                    try:
                        combination = next(combination_generator)
                        futures.append(executor.submit(process_combination, combination, tested_combinations, attempts, attempts_lock, all_combinations))
                    except StopIteration:
                        break  # Sai do loop interno se não houver mais combinações

                    # Monitorar tentativas a cada 100 combinações
                    if len(futures) % 100 == 0:
                        elapsed_time = time.time() - start_time
                        combinations_per_minute = (attempts.value / elapsed_time) * 60
                        print(f"Combinações realizadas: {attempts.value} | Taxa: {combinations_per_minute:.2f} combinações/minuto")

                found_mnemonic = None
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        found_mnemonic = result
                        break  # Sai do loop interno se o endereço for encontrado

                # Salvar todas as combinações da seed phase
                all_combinations_dict = dict(all_combinations)
                with open(all_combinations_file, "w") as f:
                    json.dump(all_combinations_dict, f, indent=4)

                if found_mnemonic:
                    # Salvar vencedor
                    os.makedirs(vencedor_pasta, exist_ok=True)
                    with open(os.path.join(vencedor_pasta, "vencedor.txt"), "w") as f:
                        f.write(f"Seed Phase: {found_mnemonic}\nEndereço Alvo: {target_address}")
                    break  # Sai do loop externo se o endereço for encontrado

if __name__ == "__main__":
    print('bip39 private key combinador V1')
    print('Gera uma chave privada para um endereço específico.')
    find_address_for_target(target_address)  # Remove o loop while True
