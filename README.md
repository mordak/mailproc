![](https://github.com/mordak/mailproc/workflows/Build/badge.svg)

# mailproc

mailproc reads email on stdin and takes actions based on its contents. It can be used to file email in different folders based on content, drop unwanted mail, or execute other tasks based on mail content. It is intended as a replacement for procmail.

Mail handling rules are specified in a [TOML](https://github.com/toml-lang/toml) formatted configuration file, stored in `$HOME/.mailproc.conf`.

The configuration file consists of a version number (1), and an array of rules. Each rule must match the following specification, as given in the program source:

```rust
struct Rule {
    headers: Option<Vec<HashMap<String, String>>>,
    body: Option<Vec<Vec<String>>>,
    raw: Option<Vec<Vec<String>>>,
    action: Option<Vec<Vec<String>>>,
    filter: Option<Vec<String>>,
}
```

All elements of a rule are optional. An empty rule matches all messages and performs no actions (the message is dropped). Messages which match no rules are dropped. A rule matches if the `headers`, `body`, and `raw` parts of the rule each match, or are omitted. Each rule element is described below:

* `headers`: An array of tables specifying header elements to match, and a regular expression to match them against. In order for the `headers` to match, *any* of the provided tables must have *all* of its header elements matched. For example, the table `{ From = "you@example\\.com", To = "me@example\\.com" }` will match if both the From and To message headers match the given patterns. Specify multiple tables to match on any of the sets of header values.

* `body`: An array of sets of regular expressions to match in the message body. Like `headers`, `body` will match of *any* of the sets of regular expressions have *all* of their expressions match.

* `raw`: An array of sets of regular expressions to match against the raw message. Like `body`, but matches the entire raw message.

* `action`: An array of commands to execute. Each command is specified as an array of strings, one string per command argument, and the email message will be provided to the command on stdin. For example, to run the dovecot `deliver` command, you could provide an action like `["/usr/local/libexec/dovecot/deliver", "-d", "todd"]`. 

* `filter`: A command specified as an array of strings, one string per argument. If provided, the message will be passed through the filter program and the output will be used to match the rest of the rule.

A configuration file could look like the following:

```toml
# Configuration file format version
version = 1

# File mail from mailinglist.example.com in folder mailinglist
[[rules]]
action = [
 ["/usr/local/libexec/dovecot/deliver", "-d", "todd", "-m", "mailinglist"],
]
headers = [
{ List-ID = "mailinglist\\.example\\.com" },
]

# Rules that have no action mean the message will be dropped. Each table in 
# the headers is tested for matches independently, and if all of the patterns
# in a table match then the headers match. So mail with a From matching "AnnoyingSender"
# OR a Subject of exactly "Buy pills online" will match this rule.
[[rules]]
headers = [
{ From = "AnnoyingSender" },
{ Subject = "^Buy pills online$" },
]

# Match spam with either of these specific phrases anywhere in the raw message text.
# Again, no action means the message will be dropped.
[[rules]]
raw = [
 ["a large sum of money"],
 ["limited time offer"],
]

# Rules can match on headers, body, raw, or any combination.
# Here, any email where the From and To match "me@mydomain.com" AND
# which have body text matching "Dear me@mydomain" OR "Special offer"
# will match the rule and the action will run.
[[rules]]
action = [
 ["/usr/local/libexec/dovecot/deliver", "-d", "todd", "-m", "junk"],
]
headers = [
{ From = "me@mydomain\\.com", To = "me@mydomain\\.com" },
]
body = [
 ["Dear me@mydomain"],
 ["Special offer"],
]

# Messages can be passed through a filter before matching.
# Here we pass the message through spamassassin and check the output
# for 'X-Spam-Status: Yes' in the headers.
[[rules]]
action = [
 ["/usr/local/libexec/dovecot/deliver", "-d", "todd", "-m", "junk"],
]
filter = ["/usr/local/bin/spamc"]
headers = [
{ X-Spam-Status = "Yes" },
]

# Rules with no headers, body, or raw parts always match, and multiple actions can be specified.
# This is the default action.
[[rules]]
action = [
 ["/usr/local/libexec/dovecot/deliver", "-d", "todd"],
 ["/usr/local/bin/notifynewmail"],
]
```

A configuration file can be tested using the `-t` option. The config test will parse `mailproc.conf` and verify that the program given in any `action` or `filter` rule elements exists and is executable, and that any regular expressions found in the `headers`, `body` and `raw` sections parse correctly. A successful test will print `Config OK` and return exit status `0`. A failed test will print `Config FAIL` and return exit status `1`, along with any error output.

```
$ mailproc -t                                                                           
Config OK
$ echo $?
0
```

To pass mail through `mailproc`, a `.forward` file can be used:

```
$ cat $HOME/.forward
|/usr/local/bin/mailproc
```

