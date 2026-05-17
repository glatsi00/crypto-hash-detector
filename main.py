import argparse
import hashlib
import itertools
import re
import string


HASH_ALGORITHMS = {
    "md5": {"length": 32, "pattern": re.compile(r"^[a-fA-F0-9]{32}$")},
    "sha1": {"length": 40, "pattern": re.compile(r"^[a-fA-F0-9]{40}$")},
    "sha224": {"length": 56, "pattern": re.compile(r"^[a-fA-F0-9]{56}$")},
    "sha256": {"length": 64, "pattern": re.compile(r"^[a-fA-F0-9]{64}$")},
    "sha384": {"length": 96, "pattern": re.compile(r"^[a-fA-F0-9]{96}$")},
    "sha512": {"length": 128, "pattern": re.compile(r"^[a-fA-F0-9]{128}$")},
}


DEFAULT_WORDS = [
    "password",
    "Password",
    "password123",
    "admin",
    "root",
    "test",
    "secret",
    "qwerty",
    "letmein",
    "hello",
    "ahoj",
    "heslo",
    "1234",
    "12345",
    "123456",
    "123456789",
]


def hash_text(text: str, algorithm: str) -> str:
    """Return a hexadecimal hash for text using the selected algorithm."""
    algorithm = algorithm.lower()
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Nepodporovany algoritmus: {algorithm}")

    hasher = hashlib.new(algorithm)
    hasher.update(text.encode("utf-8"))
    return hasher.hexdigest()


def detect_hash(value: str) -> list[str]:
    """Detect likely hash algorithms by hexadecimal format and length."""
    value = value.strip()
    return [
        name
        for name, info in HASH_ALGORITHMS.items()
        if len(value) == info["length"] and info["pattern"].match(value)
    ]


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return DEFAULT_WORDS

    with open(path, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def crack_with_wordlist(hash_value: str, algorithms: list[str], words: list[str]) -> tuple[str, str] | None:
    target = hash_value.lower()
    for word in words:
        for algorithm in algorithms:
            if hash_text(word, algorithm) == target:
                return word, algorithm
    return None


def crack_bruteforce(
    hash_value: str,
    algorithms: list[str],
    max_length: int,
    charset: str,
) -> tuple[str, str] | None:
    target = hash_value.lower()
    for length in range(1, max_length + 1):
        for chars in itertools.product(charset, repeat=length):
            candidate = "".join(chars)
            for algorithm in algorithms:
                if hash_text(candidate, algorithm) == target:
                    return candidate, algorithm
    return None


def ask_menu_choice() -> str:
    print("\nVyber akci:")
    print("1 - Text -> hash")
    print("2 - Rozpoznat hash a zkusit najit puvodni text")
    print("3 - Konec")
    return input("> ").strip()


def encrypt_interactive() -> None:
    text = input("Zadej text: ")
    algorithms = ", ".join(HASH_ALGORITHMS)
    algorithm = input(f"Vyber algoritmus ({algorithms}): ").strip().lower()

    try:
        print(f"\n{algorithm}: {hash_text(text, algorithm)}")
    except ValueError as error:
        print(f"Chyba: {error}")


def detect_interactive() -> None:
    hash_value = input("Zadej hash: ").strip()
    candidates = detect_hash(hash_value)

    if not candidates:
        print("Hash se nepodarilo rozpoznat. Podporovane jsou hexadecimalni MD5/SHA hashe.")
        return

    print(f"Pravdepodobny typ: {', '.join(candidates)}")
    print("Poznamka: hash nejde desifrovat. Program muze jen hadat puvodni text a porovnavat hashe.")

    use_wordlist = input("Zkusit slovnikovy utok? [Y/n]: ").strip().lower()
    if use_wordlist in ("", "y", "yes", "a", "ano"):
        path = input("Cesta ke slovniku, nebo Enter pro maly vestaveny slovnik: ").strip() or None
        try:
            result = crack_with_wordlist(hash_value, candidates, load_wordlist(path))
        except OSError as error:
            print(f"Slovnik nejde nacist: {error}")
            result = None

        if result:
            text, algorithm = result
            print(f"Nalezeno: '{text}' ({algorithm})")
            return

        print("Ve slovniku nebyla nalezena shoda.")

    use_bruteforce = input("Zkusit kratky brute force? [y/N]: ").strip().lower()
    if use_bruteforce in ("y", "yes", "a", "ano"):
        max_length_text = input("Maximalni delka textu (doporuceno 4 nebo mene): ").strip()
        try:
            max_length = int(max_length_text)
        except ValueError:
            print("Delka musi byt cislo.")
            return

        if max_length > 5:
            print("Kvuli rychlosti a bezpecnosti je maximum v tomto programu 5 znaku.")
            return

        charset_choice = input("Znakova sada [digits/lower/all] (default lower): ").strip().lower()
        if charset_choice == "digits":
            charset = string.digits
        elif charset_choice == "all":
            charset = string.ascii_letters + string.digits
        else:
            charset = string.ascii_lowercase

        result = crack_bruteforce(hash_value, candidates, max_length, charset)
        if result:
            text, algorithm = result
            print(f"Nalezeno: '{text}' ({algorithm})")
        else:
            print("Brute force nenasel shodu.")


def run_interactive() -> None:
    print("Hash detector / generator")
    while True:
        choice = ask_menu_choice()
        if choice == "1":
            encrypt_interactive()
        elif choice == "2":
            detect_interactive()
        elif choice == "3":
            print("Hotovo.")
            break
        else:
            print("Neplatna volba.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rozpozna hexadecimalni MD5/SHA hash a umi vytvorit hash z textu."
    )
    subparsers = parser.add_subparsers(dest="command")

    hash_parser = subparsers.add_parser("hash", help="Vytvori hash z textu.")
    hash_parser.add_argument("text", help="Text k zahashovani.")
    hash_parser.add_argument(
        "-a",
        "--algorithm",
        choices=sorted(HASH_ALGORITHMS),
        default="sha256",
        help="Hashovaci algoritmus.",
    )

    detect_parser = subparsers.add_parser("detect", help="Rozpozna typ hashe.")
    detect_parser.add_argument("hash_value", help="Hash k rozpoznani.")

    crack_parser = subparsers.add_parser("crack", help="Zkusi najit puvodni text hashe.")
    crack_parser.add_argument("hash_value", help="Hash k prolomeni.")
    crack_parser.add_argument("-w", "--wordlist", help="Cesta ke slovniku.")
    crack_parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Po slovniku zkusi kratky brute force.",
    )
    crack_parser.add_argument(
        "--max-length",
        type=int,
        default=3,
        help="Maximalni delka brute force kandidata. Maximum je 5.",
    )
    crack_parser.add_argument(
        "--charset",
        choices=("digits", "lower", "all"),
        default="lower",
        help="Znakova sada pro brute force.",
    )
    return parser


def run_cli(args: argparse.Namespace) -> None:
    if args.command == "hash":
        print(hash_text(args.text, args.algorithm))
        return

    if args.command == "detect":
        candidates = detect_hash(args.hash_value)
        if candidates:
            print(", ".join(candidates))
        else:
            print("neznamy/nepodporovany format")
        return

    if args.command == "crack":
        candidates = detect_hash(args.hash_value)
        if not candidates:
            print("Hash se nepodarilo rozpoznat.")
            return

        result = crack_with_wordlist(args.hash_value, candidates, load_wordlist(args.wordlist))
        if not result and args.bruteforce:
            if args.max_length > 5:
                raise ValueError("Maximalni delka brute force je 5.")
            charset_map = {
                "digits": string.digits,
                "lower": string.ascii_lowercase,
                "all": string.ascii_letters + string.digits,
            }
            result = crack_bruteforce(
                args.hash_value,
                candidates,
                args.max_length,
                charset_map[args.charset],
            )

        if result:
            text, algorithm = result
            print(f"{text} ({algorithm})")
        else:
            print("nenalezeno")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command:
        run_cli(args)
    else:
        run_interactive()


if __name__ == "__main__":
    main()
