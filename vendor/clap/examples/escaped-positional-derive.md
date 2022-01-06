*Jump to [source](escaped-positional-derive.rs)*

**This requires enabling the `derive` feature flag.**

You can use `--` to escape further arguments.

Let's see what this looks like in the help:
```bash
$ escaped-positional-derive --help
clap [..]
A simple to use, efficient, and full-featured Command Line Argument Parser

USAGE:
    escaped-positional-derive[EXE] [OPTIONS] [-- <SLOP>...]

ARGS:
    <SLOP>...    

OPTIONS:
    -f               
    -h, --help       Print help information
    -p <PEAR>        
    -V, --version    Print version information
```

Here is a baseline without any arguments:
```bash
$ escaped-positional-derive
-f used: false
-p's value: None
'slops' values: []
```

Notice that we can't pass positional arguments before `--`:
```bash
$ escaped-positional-derive foo bar
? failed
error: Found argument 'foo' which wasn't expected, or isn't valid in this context

USAGE:
    escaped-positional-derive[EXE] [OPTIONS] [-- <SLOP>...]

For more information try --help
```

But you can after:
```bash
$ escaped-positional-derive -f -p=bob -- sloppy slop slop
-f used: true
-p's value: Some("bob")
'slops' values: ["sloppy", "slop", "slop"]
```

As mentioned, the parser will directly pass everything through:
```bash
$ escaped-positional-derive -- -f -p=bob sloppy slop slop
-f used: false
-p's value: None
'slops' values: ["-f", "-p=bob", "sloppy", "slop", "slop"]
```
