import argparse
import hashlib
import sys
from string import ascii_lowercase, digits
from itertools import product
from typing import Optional, Collection


DEFAULT_ALPHABET = digits + ascii_lowercase


def crack_sha1(hex_digest: str, length: int, salt: str, alphabet: Collection[str]) -> Optional[str]:
    assert len(hex_digest) == hashlib.sha1().digest_size * 2
    n = len(alphabet) ** length
    i = 0
    matching_password = None
    print(f'length={length} alphabet ({len(alphabet)}) = {alphabet}', file=sys.stderr)
    print(f'num possible password n = {len(alphabet)}^{length} = {n}', file=sys.stderr)
    for comb in product(alphabet, repeat=length):
        i += 1
        password = ''.join(comb)
        # print(password)
        data = password + salt
        raw_data = data.encode('utf-8')
        m = hashlib.sha1()
        m.update(raw_data)
        if m.hexdigest() == hex_digest:
            matching_password = password
            break
    print(f'tried i={i} passwords out of n={n} possible', file=sys.stderr)
    return matching_password


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Crack an SHA-1 password hash using brute force.',
    )
    parser.add_argument(
        '--hash',
        help='The SHA-1 password hash (40 lowercase hex characters)',
        required=True,
    )
    parser.add_argument(
        '--length',
        help='The length of the password',
        required=True,
        type=int,
    )
    parser.add_argument(
        '--salt',
        help='Optional known password suffix salt, i.e., hash = sha1(password + salt)',
        default='',
    )
    parser.add_argument(
        '--alphabet',
        help='The password alphabet',
        default=DEFAULT_ALPHABET,
    )
    args = parser.parse_args()
    cracked_password = crack_sha1(
        hex_digest=args.hash,
        length=args.length,
        salt=args.salt,
        alphabet=args.alphabet,
    )
    if cracked_password is None:
        print('No SHA-1 digest match found!', file=sys.stderr)
        sys.exit(1)
    else:
        print(cracked_password)
