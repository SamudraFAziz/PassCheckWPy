import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check API and try again')
    return res

def get_pass_leak_count(response, hash_to_check):
    parsed_hashes = (line.split(':') for line in response)
    print(parsed_hashes)
    for h, count in parsed_hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_pass_leak_count(response.text.splitlines(), tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was fou  {count} times... get pwned lol')
        else:
            print(f'{password} was NOT found. Nerd')
    return 'done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
