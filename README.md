# argon2-go-withsecret
Why? Because your attacker has hardware that can test 10 billion passwords per second.

Supports creating an argon2 context from encoding thus allowing verify with secret and additional data.
The use of a secret means the attacker cannot break your passwords no matter what hardware he has.
It has a default mode of argon2id, memory option of 65536 and parallelism option of 2 which gives 64Mbytes mem usage and gives about 400ms per op on a cheap dual core laptop. ( 2 attacker trials per second on laptop).
The calls to the library are serialized with a Mutex lock to provide automatic throttling and guaranteed stable memory usage under burst load conditions.
Ultimately it calls the C library argon2 so it is as fast as it gets.

But, should the attacker have obtained the secret,
the argon2 algorithm is designed to be hard for specialist hardware to speed up.

See [Ballon Hashing] (https://eprint.iacr.org/2016/027.pdf)
TLDR; You must use mode argon2id with largest memory you can afford.

For example an attacker can rent GPU accelerated AWS EC2 instances (g3.16xlarge) with say 8000 cores and 488 Gbytes.
With the default 64Mbytes per password trial,
8000 cores will need 512GBytes of memory and hopefully the memory bus transfers will limit the throughput.
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
```go
import (
	"fmt"
	"github.com/learnfromgirls/argon2-go-withsecret"
	"log"
)
```

### Encoded hash with default configuration (argon2id 64Mbytes)

```go
	ctx := argon2_go_withsecret.NewContext()
	s, err := ctx.HashEncoded([]byte("password"), []byte("somesalt"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", s)
	ctx4v := argon2_go_withsecret.NewContext()
	ok, err := ctx4v.VerifyEncoded(s, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", ok)
```


### Encoded hash with custom configuration and secret (argon2id 256Mbytes secret)

```go
	ctx := argon2_go_withsecret.NewContext(argon2_go_withsecret.ModeArgon2id)
	ctx.SetMemory(1 << 18)
	ctx.SetParallelism(2)
	ctx.SetSecret([]byte("secret"))
	s, err := ctx.HashEncoded([]byte("password"), []byte("somesalt"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", s)

	//verifier mode, memory, parallelism etc will be set from encoding so no need to set here.
	ctx4v := argon2_go_withsecret.NewContext()
	ctx4v.SetSecret([]byte("secret"))
	ok, err := ctx4v.VerifyEncoded(s, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v detected mode=%v\n", ok, ctx4v.GetMode())
```

## Limitations
A deliberately slow hash function still requires the password as input. If that password is transmitted from
a web browser to the server before hashing then a Man In The Middle can just read the cleartext password.
Companies can and do use remote web proxies such as ForcePoint to decrypt, inspect, and reencrypt your https traffic using dynamically generated "fake" SSL certificates.
To defend against this you could try hashing on the client but there is no efficient memoryhard implementation available for the browser.
[MAKWA] (http://www.bolet.org/makwa/makwa-spec-20150422.pdf) offers hope via delegation.

[SRP] (https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol) is a password based authenticated key exchange that will protect against Man In The Middle and will provide application level encryption keys.
Again the hash function cannot be hard as it is performed by the feeble client. Unfortunately the server verifier is not hash protected.
However this can be fixed. The server verifier is not required until after the client has sent proof of the session key and so there is still the chance to involve the serverside argon2id hash
now that a shared key is available. E.g server could brute force to find v given clients proof and clues of v. Then run v through argon2id to verify.





