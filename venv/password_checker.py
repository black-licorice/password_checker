import requests
import hashlib
import sys


def main(args):
    for password in args:
        count = check_pass(password)
        if count:
            print(f"{password} was found {count} times, you should change it...")
        else:
            print(f"{password} was not found, you are safe!")
    return 0


def request_data(hashed_str):
    url = 'https://api.pwnedpasswords.com/range/' + hashed_str
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check API")
    return res


def get_pass_count(hashes, tail_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == tail_to_check:
            return count
    return 0


def check_pass(password):
    sha1_hashed_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars, tail = sha1_hashed_pass[:5], sha1_hashed_pass[5:]
    response = request_data(first5_chars)
    return get_pass_count(response, tail)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(main(sys.argv[1:]))
    else:
        print("Usage: python password_checker.py <password>")
        exit(1)
