from algorithms_type.aes import aes_main
from algorithms_type.rc4_stream_cipher import rc4_main
from algorithms_type.rsa import rsa_main
from algorithms_type.caesar_cipher import caesar_main
from algorithms_type.vigenere_cipher import vigenere_main
from config import ALGORITHM_METADATA


class AlgorithmSelector:
    def __init__(self):
        self.generated_metadata = {}

        self.algorithms = {
            "AES": aes_main,
            "RC4 Stream Cipher": rc4_main,
            "RSA": rsa_main,
            "Caesar Cipher": caesar_main,
            "Vigenere Cipher": vigenere_main,
        }

    def run_algorithm(self, algorithm_name, message, key=None, include_special_chars=None):
        if algorithm_name not in self.algorithms:
            raise ValueError(f"Algorithm '{algorithm_name}' is not available.")

        algorithm_metadata = ALGORITHM_METADATA[algorithm_name]
        key_type = algorithm_metadata["key_type"]

        if key_type in ["int", "str"]:
            if algorithm_name in ["Caesar Cipher", "Vigenere Cipher"]:
                return self.algorithms[algorithm_name](message, key, include_special_chars)
            else:
                return self.algorithms[algorithm_name](message, key)
        else:
            result = self.algorithms[algorithm_name](message)

            if algorithm_metadata.get("generated_key", False):
                if algorithm_name == "AES":
                    self.generated_metadata[algorithm_name] = {
                        "key": result["key"],
                        "iv": result["iv"]
                    }
                elif algorithm_name == "RSA":
                    self.generated_metadata[algorithm_name] = {
                        "public_key": result["public_key"],
                        "private_key": result["private_key"],
                        "byte_lengths": result["byte_lengths"]
                    }

            return result["encrypted_message"]

    def get_generated_key(self, algorithm_name):
        if algorithm_name == "AES":
            return {
                "key": self.generated_metadata["AES"]["key"],
                "iv": self.generated_metadata["AES"]["iv"]
            }
        elif algorithm_name == "RSA":
            public_key = self.generated_metadata["RSA"]["public_key"]
            private_key = self.generated_metadata["RSA"]["private_key"]
            return {
                "public_key": f"{public_key[0]},{public_key[1]}",
                "private_key": f"{private_key[0]},{private_key[1]}",
            }
        return None


