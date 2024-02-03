# Depot

A key-value store for the command-line, with optional encryption.

## Dependencies

Requires sqlite3. Development libraries for sqlite3 may also be required to
build from source. See necessary OS-specific packages below:

Debian/Ubuntu: `apt install sqlite3 libsqlite3-dev`

Fedora: `dnf install sqlite sqlite-devel`

OpenBSD: `pkg_add sqlite3`

## Building

`cargo build --release`

Only compatible with Linux/Unix.

## Example Usage

`depot stow newinfo` (Waits for data entry on stdin)

`echo shhh | depot stow -s secret` (Will prompt for password)

`depot fetch newinfo` (Prints to stdout)

`depot fetch -n fetch secret | xclip` (Prints without trailing newline. Will
prompt for password.)


```
Usage: depot [-nsh?] <action> <key>

Actions:
    stow        Read a value from stdin and associate it with the given key
    fetch       Print the value associated with the given key to stdout
    drop        Remove the given key from the depot

Options:
    -n          No newline character will be printed after fetching a value
    -s          The provided value is secret and will be encrypted
    -h, -?      Print this help message and exit

Environment Variables:
    DEPOT_PATH  Specifies a non-standard path to the depot's database
                (Defaults to $XDG_CONFIG_HOME/depot/depot.db)
    DEPOT_PASS  Specifies the password to be used to encrypt/decrypt values
                (Be careful with this! It is certainly less secure!)
```
