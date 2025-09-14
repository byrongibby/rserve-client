# QAP v1 message example

## QAP layout

[QAP1 (quad attributes protocol v1)](https://rforge.net/Rserve/dev.html) is a message oriented protocol, i.e. the initiating side (here the client) sends a message and awaits a response. The message contains both the action to be taken and any necessary data. The response contains a response code and any associated data. Every message consists of a header and data part (which can be empty). The header is structured as follows:

```
(data type | is large?) length of message (4-8 bytes)
(expression type | has attribute? | is long?) length of expression (4-8 bytes)
expression data (multiple of 4 bytes)
```

## Example

```
list(foo = list(1L, 'Z', FALSE), 'bar' = pi, 'baz')
```

Notice the padding for arrays of strings and logicals used to maintain a length that is a multiple of 4 bytes.

```
# Message header
0a 58 00 00 (DT_SEXP) 88

# Vector expression header
90 54 00 00 (XT_VECTOR | XT_HAS_ATTR) 84

  # Attribute
  15 1c 00 00 (XT_LIST_TAG) 28
  22 0c 00 00 (XT_ARRAY_STR) 12
  66 6f 6f 00 foo
  62 61 72 00 bar
  00 01 01 01 NULL 
  13 08 00 00 (XT_SYMNAME) 8
  6e 61 6d 65
  73 00 00 00 names

  # Vector expression data

  # Nested vector
  10 1c 00 00 (XT_VECTOR) 28
    20 04 00 00 (XT_ARRAY_INT) 4
    01 00 00 00 1L

    22 04 00 00 (XT_ARRAY_STR) 4
    5a 00 01 01 Z

    24 08 00 00 (XT_ARRAY_BOOL) 8
    01 00 00 00 FALSE
    00 ff ff ff

  21 08 00 00 (XT_ARRAY_DOUBLE) 8
  18 2d 44 54
  fb 21 09 40 3.14

  22 04 00 00 (XT_ARRAY_STR) 4
  62 61 7a 00 baz
```
