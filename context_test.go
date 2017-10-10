package argon2_go_withsecret


import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {
	vectors := []struct {
		ctx      *A2Context
		password []byte
		salt     []byte
		hash     string
	}{

		{
			&A2Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2i,
				Version:        Version10,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd",
		},
		{
			&A2Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2i,
				Version:        Version13,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
		},
		{
			&A2Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2d,
				Version:        Version10,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b",
		},
		{
			&A2Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2d,
				Version:        Version13,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
		},
		{
			&A2Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2id,
				Version:        Version10,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0",
		},
		{
			&A2Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2id,
				Version:        Version13,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
		},
	}

	for i, v := range vectors {
		expected, _ := hex.DecodeString(v.hash)
		ctx  := NewContext()
		ctx.SetFromA2Context(v.ctx)
		hash, err := ctx.Hash(v.password, v.salt)
		if err != nil {
			t.Errorf("received error: %s (%d)", err, i)
		}
		if !bytes.Equal(hash, expected) {
			t.Errorf("%d:      got: %x", i, hash)
			t.Errorf("%d: expected: %x", i, expected)
		}
	}

}

func TestHashEncoded(t *testing.T) {
	ctx := NewContext(ModeArgon2d)

	password := []byte("somepassword")
	salt := []byte("somesalt")

	expected := "$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$THaZx86KeqT+xuygENqvxaYIk3zu4wH0UmqzBL/wrdQ"

	s, err := ctx.HashEncoded( password, salt)
	if err != nil {
		t.Fatal(err)
	}
	if s != expected {
		t.Fatalf("HashEncoded: got %q  want %q", s, expected)
	}

	ctx.SetVersion(Version10)
	expected = "$argon2d$v=16$m=4096,t=3,p=1$c29tZXNhbHQ$9zHzndOtdbtKI3zBlrpnnpjNj9FnrkeiK43kb8NuuMc"

	s, err = ctx.HashEncoded( password, salt)
	if err != nil {
		t.Fatal(err)
	}
	if s != expected {
		t.Fatalf("HashEncoded: got %q  want %q", s, expected)
	}
}

func TestHash_Error(t *testing.T) {
	ctx := NewContext()
	_, err := ctx.Hash( []byte("password"), []byte("s"))
	if ! ErrSaltTooShort.Equals(err) {
		t.Errorf("got %q  want %q", err, ErrSaltTooShort)
	}

	ctx = NewContext()
	ctx.SetMode(99)
	_, err = ctx.Hash( []byte("password"), []byte("somesalt"))
	if ! ErrIncorrectType.Equals(err) {
		t.Errorf("got %q  want %q", err, ErrIncorrectType)
	}

	ctx = NewContext()
	ctx.SetMemory(4)
	_, err = ctx.Hash( []byte("password"), []byte("somesalt"))
	if !ErrMemoryTooLittle.Equals(err) {
		t.Errorf("got %q  want %q", err, ErrMemoryTooLittle)
	}
}

func TestVerify(t *testing.T) {
	ctx := NewContext(ModeArgon2d)
	testVerify(t, ctx)

	ctx.SetMode(ModeArgon2i)
	testVerify(t, ctx)
}

func TestVerifyEncoded(t *testing.T) {
	ctx := NewContext(ModeArgon2d)
	testVerifyEncoded(t, ctx)

	ctx.SetMode(ModeArgon2i)
	testVerifyEncoded(t, ctx)
}

func TestVerify2idsecret(t *testing.T) {
	ctx := NewContext(ModeArgon2id)
	ctx.SetSecret ([]byte("somesecret"))
	testVerify(t, ctx)
}

func TestVerifyEncoded2idsecret(t *testing.T) {
	ctx := NewContext(ModeArgon2id)
	ctx.SetSecret ([]byte("somesecret"))
	testVerifyEncoded(t, ctx)
}

func TestFlagClearPassword(t *testing.T) {
	ctx := NewContext()
	ctx.SetFlags(FlagDefault)
	password := []byte("somepassword")
	salt := []byte("somesalt")

	ctx.Hash( password, salt)
	if !bytes.Equal([]byte("somepassword"), password) {
		t.Fatalf("password slice is modified")
	}

	ctx.SetFlags(FlagClearPassword)
	ctx.Hash( password, salt)
	if !bytes.Equal(make([]byte, len(password)), password) {
		t.Fatalf("password slice is not cleared")
	}
}

func TestFlagClearSecret(t *testing.T) {
	ctx := NewContext()
	ctx.SetFlags(FlagDefault)
	ctx.SetSecret([]byte("somesecret"))
	password := []byte("somepassword")
	salt := []byte("somesalt")

	ctx.Hash( password, salt)
	if !bytes.Equal([]byte("somesecret"), ctx.Secret) {
		t.Fatalf("secret slice is modified")
	}

	ctx.SetFlags(FlagClearSecret)
	ctx.Hash(password, salt)
	if !bytes.Equal(make([]byte, len(ctx.Secret)), ctx.Secret) {
		t.Fatalf("secret slice is not cleared")
	}
}

func testVerifyEncoded(t *testing.T, ctx *Context) {
	s, err := ctx.HashEncoded( []byte("somepassword"), []byte("somesalt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("encoded=%s ctx=%+v a2ctx=%+v",s, ctx, ctx.a2ctx)
	pw := []byte("somepassword")
	ok, err := ctx.VerifyEncoded(s, pw)
	if err != nil {
		t.Logf("encoded=%s",s)
		t.Fatal(err)
	}
	if !ok {
		t.Logf("encoded=%s ctx=%+v a2ctx=%+v",s, ctx, ctx.a2ctx)
		t.Errorf("VerifyEncoded(s, []byte(%q)) = false  want true", pw)
	}

	pw = []byte("someotherpassword")
	ok, err = ctx.VerifyEncoded(s, pw)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("VerifyEncoded(s, []byte(%q)) = true  want false", pw)
	}
}

func testVerify(t *testing.T, ctx *Context) {
	password := []byte("hunter2")
	salt := []byte("somesalt")
	hash, err := ctx.Hash( password, salt)
	if err != nil {
		t.Fatal(err)
	}

	// Test correct password
	ok, err := ctx.Verify( hash, password, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("Verify(..) = false  want true (%v)", ctx)
	}

	// Test incorrect password
	ok, err = ctx.Verify( hash, []byte("hunter3"), salt)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("Verify(badpw) = true  want false (%v)", ctx)
	}

	// Test incorrect salt
	ok, err = ctx.Verify( hash, password, []byte("somepepper"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("Verify(badsalt) = true  want false (%v)", ctx)
	}
}
