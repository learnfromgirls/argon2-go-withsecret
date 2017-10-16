package argon2_go_withsecret
import (
   "fmt"
   "log"
)

func example1() {

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
}


func example2() {
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
}
