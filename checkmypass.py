import sys
import hashlib
import requests


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching data: {res.status_code}, check the API and try again')
    return res


def get_leaks_count(hash_data, hash_to_check):
    hash_data = (line.split(':') for line in hash_data.text.splitlines())
    for h, count in hash_data:
        if h == hash_to_check:
            return count
    return 0


def pwd_api_data_check(actual_password):
    sha1format_password = hashlib.sha1(
        actual_password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1format_password[:5], sha1format_password[5:]
    data_request = request_api_data(first5_char)
    # check password if it exists in request_api_data response.
    return get_leaks_count(data_request, tail)


def main_request(args):
    for password in args:
        leaks_count = pwd_api_data_check(password)
        if leaks_count:
            print(
                f'{password} was leaked {leaks_count} times... you should probably change it.')
        else:
            print(f'{password} has NOT been leaked. All good!')
    return 'All checks have been done!'


if __name__ == '__main__':
    sys.exit(main_request(input('What passwords do you want to check? ').split()))
