# argon2-go-withsecret
Support creating an argon2 context from encoding thus allowing verify with secret and additional data.
Has a default memory option is 32768 which gives 32Mbytes mem usage and about 100mS per op on a laptop. ( 10 attacker trials per second on laptop).
Ultimately calls a the C library argon2 so is a fast as it gets.

## Installation

Install argon2 C library as detailed in
[go-argon2](https://github.com/tvdburgt/go-argon2).

Then
```
$ sudo ldconfig
```

Install go-argon2 go bindings as detailed in
[go-argon2](https://github.com/tvdburgt/go-argon2).

Test everything is installed correctly:

```
$ cd $GOCODE/src/github.com/learnfromgirls/argon2-go-withsecret/
$ go test
$ go test -bench=.
Note that some of the benchmarks (m19,m20,m21)require 512Mb, 1024Mb and 2048Mb so will correctly fail with a memory error on
an AWS nano or micro EC2 instance.
```

## Usage
both raw hashes and encoded hashes are supported via Context methods.

### Encoded hash with default configuration (argon2id 32Mbytes)

```go
    ctx := NewContext()
    s, err := ctx.HashEncoded(  []byte("password"), []byte("somesalt"))
    if err != nil {
    	log.Fatal(err)
    }

    fmt.Printf("%s\n", s)
    ok, err := ctx.VerifyEncoded(s, []byte("password"))
    if err != nil {
        	log.Fatal(err)
    }
    fmt.Printf("%v\n", ok)
```


### Encoded hash with custom configuration and secret (argon2i 64Mbytes secret)

```go
    ctx := NewContext(ModeArgon2i)
    ctx.SetMemory(1 << 16)
    ctx.SetSecret([]byte("secret"))
    s, err := ctx.HashEncoded(  []byte("password"), []byte("somesalt"))
    if err != nil {
    	log.Fatal(err)
    }

    fmt.Printf("%s\n", s)
    ok, err := ctx.VerifyEncoded(s, []byte("password"))
    if err != nil {
    	log.Fatal(err)
    }
    fmt.Printf("%v\n", ok)
```




