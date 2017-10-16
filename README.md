# argon2-go-withsecret
Supports creating an argon2 context from encoding thus allowing verify with secret and additional data.
Has a default memory option of 32768 which gives 32Mbytes mem usage and about 100mS per op on a laptop. ( 10 attacker trials per second on laptop).
Ultimately it calls the C library argon2 so is as fast as it gets.
The use of a secret means the attacker cannot break your passwords with any hardware.

But, should the attacker have obtained the secret,
the argon2 algorithm is designed to be hard for specialist hardware to speed up.
For example an attacker can rent GPU accelerated AWS EC2 instances (g3.16xlarge) with say 8000 cores and 488 Gbytes.
With the default 32Mbytes per password trial,
8000 cores will need 256GBytes of memory and hopefully the memory bus transfers will limit the throughput.
It will be costing the attacker $45.6 per Hour to rent the instance (spot pricing).
Changing the argon2 memory option to 256MBytes means it will still run on an AWS nano instance but the attacker
will now only be able to use less than 2000 of his 8000 cores.



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
$ go get github.com/learnfromgirls/argon2-go-withsecret
$ cd $GOCODE/src/github.com/learnfromgirls/argon2-go-withsecret/
$ go test
The above test should pass.
You may also run the benchmarks to test the higher memory options.
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




