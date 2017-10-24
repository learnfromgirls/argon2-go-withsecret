package example

import (
	"fmt"
	"github.com/learnfromgirls/argon2-go-withsecret"
	"log"
)

//default context is argon2id 64Mbytes
func example1() {

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
}

//custom config argon2id 256Mbytes parallelism 2 and a secret
func example2() {
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
}

//custom config argon2id 256Mbytes parallelism 1 and a secret
func example3() {
    ctx := argon2_go_withsecret.NewContext(argon2_go_withsecret.ModeArgon2id)
    ctx.SetMemory(1 << 18)
    ctx.SetParallelism(1)
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
}

