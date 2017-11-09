package argon2_go_withsecret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/tvdburgt/go-argon2"
	"strings"
	"sync"
	"crypto/rand"
	"github.com/learnfromgirls/safesecrets"
)

var mutex = &sync.Mutex{}

const (
	ModeArgon2d int = 0
	ModeArgon2i int = 1
	ModeArgon2id int = 2
)

const (
	Version10 int = 0x10
	Version13 int = 0x13
	VersionDefault int = 0x13
)

const (
	FlagDefault int = 0
	FlagClearPassword int = 1
	FlagClearSecret int = 2
)

// Error represents the internal error code propagated from libargon2.
type Error struct {
	a2err *argon2.Error
	msg   string
}

func (e *Error) Error() string {
	return e.msg
}

func (e *Error) Equals(err error) bool {
	//faster to use the int value but this will do
	if err != nil {
		return e.msg == err.Error()
	} else {
		return false
	}
}

func NewError(err *argon2.Error) *Error {
	return &Error{err, err.Error()}
}

var (
	ErrOutputPtrNull         *Error = NewError(&argon2.ErrOutputPtrNull)
	ErrOutputTooShort        *Error = NewError(&argon2.ErrOutputTooShort)
	ErrOutputTooLong         *Error = NewError(&argon2.ErrOutputTooLong)
	ErrPwdTooShort           *Error = NewError(&argon2.ErrPwdTooShort)
	ErrPwdTooLong            *Error = NewError(&argon2.ErrPwdTooLong)
	ErrSaltTooShort          *Error = NewError(&argon2.ErrSaltTooShort)
	ErrSaltTooLong           *Error = NewError(&argon2.ErrSaltTooLong)
	ErrAdTooShort            *Error = NewError(&argon2.ErrAdTooShort)
	ErrAdTooLong             *Error = NewError(&argon2.ErrAdTooLong)
	ErrSecretTooShort        *Error = NewError(&argon2.ErrSecretTooShort)
	ErrSecretTooLong         *Error = NewError(&argon2.ErrSecretTooLong)
	ErrTimeTooSmall          *Error = NewError(&argon2.ErrTimeTooSmall)
	ErrTimeTooLarge          *Error = NewError(&argon2.ErrTimeTooLarge)
	ErrMemoryTooLittle       *Error = NewError(&argon2.ErrMemoryTooLittle)
	ErrMemoryTooMuch         *Error = NewError(&argon2.ErrMemoryTooMuch)
	ErrLanesTooFew           *Error = NewError(&argon2.ErrLanesTooFew)
	ErrLanesTooMany          *Error = NewError(&argon2.ErrLanesTooMany)
	ErrPwdPtrMismatch        *Error = NewError(&argon2.ErrPwdPtrMismatch)
	ErrSaltPtrMismatch       *Error = NewError(&argon2.ErrSaltPtrMismatch)
	ErrSecretPtrMismatch     *Error = NewError(&argon2.ErrSecretPtrMismatch)
	ErrAdPtrMismatch         *Error = NewError(&argon2.ErrAdPtrMismatch)
	ErrMemoryAllocationError *Error = NewError(&argon2.ErrMemoryAllocationError)
	ErrFreeMemoryCbkNull     *Error = NewError(&argon2.ErrFreeMemoryCbkNull)
	ErrAllocateMemoryCbkNull *Error = NewError(&argon2.ErrAllocateMemoryCbkNull)
	ErrIncorrectParameter    *Error = NewError(&argon2.ErrIncorrectParameter)
	ErrIncorrectType         *Error = NewError(&argon2.ErrIncorrectType)
	ErrOutPtrMismatch        *Error = NewError(&argon2.ErrOutPtrMismatch)
	ErrThreadsTooFew         *Error = NewError(&argon2.ErrThreadsTooFew)
	ErrThreadsTooMany        *Error = NewError(&argon2.ErrThreadsTooMany)
	ErrMissingArgs           *Error = NewError(&argon2.ErrMissingArgs)
	ErrEncodingFail          *Error = NewError(&argon2.ErrEncodingFail)
	ErrDecodingFail          *Error = NewError(&argon2.ErrDecodingFail)
	ErrThreadFail            *Error = NewError(&argon2.ErrThreadFail)
	ErrDecodingLengthFail    *Error = NewError(&argon2.ErrDecodingLengthFail)
	ErrVerifyMismatch        *Error = NewError(&argon2.ErrVerifyMismatch)
)

var (
	ErrEncodedFormat = errors.New("argon2-go-withsecret: cannot parse encodedhash")
	ErrEncodedFormatNotSixParts = errors.New("argon2-go-withsecret: cannot parse encodedhash. Not 6 parts")
	ErrEncodedFormatUnknownType = errors.New("argon2-go-withsecret: cannot parse encodedhash. Unknown Type")
	ErrEncodedFormatNoV = errors.New("argon2-go-withsecret: cannot parse encodedhash. No V")
	ErrEncodedFormatNoM = errors.New("argon2-go-withsecret: cannot parse encodedhash. No M")
	ErrEncodedFormatNoP = errors.New("argon2-go-withsecret: cannot parse encodedhash. No P")
	ErrEncodedFormatNoT = errors.New("argon2-go-withsecret: cannot parse encodedhash. No T")
	ErrEncodedFormatNotThreeSubParts = errors.New("argon2-go-withsecret: cannot parse encodedhash. Not 3 subparts")
	ErrContext = errors.New("argon2: context is nil")
	ErrPassword = errors.New("argon2: password is nil or empty")
	ErrSalt = errors.New("argon2: salt is nil or empty")
	ErrHash = errors.New("argon2: hash is nil or empty")
)

type A2Context argon2.Context

type Context struct {
	Secret         []byte // used to populate a2ctx
	AssociatedData []byte // used to populate a2ctx
	Flags          int    //used to populate a2ctx
	a2ctx          *argon2.Context
}

// NewContext initializes a new Argon2 context with reasonable defaults for sub-second hashing time.
// allows the mode to be set as an optional paramter
func NewContext(mode ...int) *Context {

	var m int = ModeArgon2id
	if len(mode) >= 1 {
		//override my preferred default mode
		m = mode[0]
	}
	context := &Context{
		Secret:         nil,
		AssociatedData: nil,
		Flags:          FlagDefault,
		a2ctx:          argon2.NewContext(m),
	}

	context.a2ctx.Memory = (1 << 16) // 64 MiB default gives about 400ms per op on normal dual core laptop
	context.a2ctx.Parallelism = 2 // 2 core

	return context
}

// NewVaultContext initializes a new Argon2 context with several seconds of hashing work time.
// Suitable for administrator, master password and vault derived secret generation
// allows the mode to be set as an optional paramter
func NewVaultContext(mode ...int) *Context {

	var m int = ModeArgon2id
	if len(mode) >= 1 {
		//override my preferred default mode
		m = mode[0]
	}
	context := &Context{
		Secret:         nil,
		AssociatedData: nil,
		Flags:          FlagDefault,
		a2ctx:          argon2.NewContext(m),
	}

	context.a2ctx.Memory = (1 << 18) // 256 MiB default
	context.a2ctx.Parallelism = 2 // 2 core
	context.a2ctx.Iterations = 20 //more that the default 3

	return context
}



func NewRandomSalt() ([] byte, error) {

	salt := make([]byte, 16) //argon salt length is fixed at 16

	_, err := rand.Read(salt)
	if err == nil {
		return salt, nil
	} else {
		return nil, err
	}
}

func argon2_type2string(a2t int) string {
	switch a2t {
	case ModeArgon2d:
		return "argon2d"
	case ModeArgon2i:
		return "argon2i"
	case ModeArgon2id:
		return "argon2id"
	default:
		return "argon2id"
	}
}

func argon2_string2type(atype string) (a2t int, err error) {
	switch atype {

	case "argon2d":
		return ModeArgon2d, nil

	case "argon2i":
		return ModeArgon2i, nil

	case "argon2id":
		return ModeArgon2id, nil
	default:
		return 0, ErrEncodedFormat
	}
}

// sets Context fields from defaults
func (ctx *Context) SetSecret(secret []byte) *Context {
	ctx.Secret = secret
	ctx.a2ctx.Secret = secret
	return ctx
}

// sets Context fields from defaults
func (ctx *Context) SetAssociatedData(ad []byte) *Context {
	ctx.AssociatedData = ad
	ctx.a2ctx.AssociatedData = ad
	return ctx
}

// sets Context fields from defaults
func (ctx *Context) SetMode(mode int) *Context {
	ctx.a2ctx.Mode = mode
	return ctx
}

// gets Context fields
func (ctx *Context) GetMode() int {
	return ctx.a2ctx.Mode
}

// sets Context fields from defaults
func (ctx *Context) SetIterations(iterations int) *Context {
	ctx.a2ctx.Iterations = iterations
	return ctx
}

// gets Context fields
func (ctx *Context) GetIterations() int {
	return ctx.a2ctx.Iterations
}


// sets Context fields from defaults
func (ctx *Context) SetVersion(version int) *Context {
	ctx.a2ctx.Version = version
	return ctx
}

// gets Context fields
func (ctx *Context) GetVersion() int {
	return ctx.a2ctx.Version
}


// sets Context fields from defaults
func (ctx *Context) SetMemory(memory int) *Context {
	ctx.a2ctx.Memory = memory
	return ctx
}

// gets Context fields
func (ctx *Context) GetMemory() int {
	return ctx.a2ctx.Memory
}

// sets Context fields from defaults
func (ctx *Context) SetParallelism(parallelism int) *Context {
	ctx.a2ctx.Parallelism = parallelism
	return ctx
}

// gets Context fields
func (ctx *Context) GetParallelism() int {
	return ctx.a2ctx.Parallelism
}


// sets Context fields from defaults
func (ctx *Context) SetFlags(flags int) *Context {
	ctx.Flags = flags
	ctx.a2ctx.Flags = flags
	return ctx
}

// sets Context fields from A2Context
func (ctx *Context) SetFromA2Context(compat *A2Context) *Context {
	ctx.a2ctx = (*argon2.Context)(compat)
	ctx.Secret = compat.Secret
	ctx.AssociatedData = compat.AssociatedData
	ctx.Flags = compat.Flags
	return ctx
}

// sets Context fields from encoded string and return binary hash in encoding.
func (ctx *Context) SetFromEncoded(encoded string) (hash []byte, salt []byte, err error) {
	var parts []string = strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, nil, ErrEncodedFormatNotSixParts
	}

	mode, err := argon2_string2type(parts[1])
	if err != nil {
		return nil, nil, ErrEncodedFormatUnknownType
	}

	ctx.a2ctx = argon2.NewContext(mode)
	var n int = 0
	n, err = fmt.Sscanf(parts[2], "v=%d", &ctx.a2ctx.Version)
	if n != 1 || err != nil {
		return nil, nil, ErrEncodedFormatNoV
	}
	//m,t,p
	var mtp []string = strings.Split(parts[3], ",")
	if len(mtp) != 3 {
		return nil, nil, ErrEncodedFormatNotThreeSubParts
	}
	n, err = fmt.Sscanf(mtp[0], "m=%d", &ctx.a2ctx.Memory)
	if n != 1 || err != nil {
		return nil, nil, ErrEncodedFormatNoM
	}
	n, err = fmt.Sscanf(mtp[1], "t=%d", &ctx.a2ctx.Iterations)
	if n != 1 || err != nil {
		return nil, nil, ErrEncodedFormatNoT
	}
	n, err = fmt.Sscanf(mtp[2], "p=%d", &ctx.a2ctx.Parallelism)
	if n != 1 || err != nil {
		return nil, nil, ErrEncodedFormatNoP
	}
	ctx.a2ctx.Secret = ctx.Secret
	ctx.a2ctx.AssociatedData = ctx.AssociatedData
	ctx.a2ctx.Flags = ctx.Flags

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])

	return hash, salt, err
}

// hash password and salt
func (ctx *Context) Hash(password []byte, salt []byte) (hash []byte, err error) {
	mutex.Lock()
	defer mutex.Unlock()
	hash, err = argon2.Hash(ctx.a2ctx, password, salt)
	return hash, err
}

// HashEncoded hashes a password and produces a crypt-like encoded string.
func (ctx *Context) HashEncoded(password []byte, salt []byte) (string, error) {

	h, e := ctx.Hash(password, salt)

	var encoded string = fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2_type2string(ctx.a2ctx.Mode),
		ctx.a2ctx.Version,
		ctx.a2ctx.Memory,
		ctx.a2ctx.Iterations,
		ctx.a2ctx.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h))

	return encoded, e
}

// Verify verifies an Argon2 hash against a plaintext password.
func (ctx *Context) Verify(hash, password, salt []byte) (bool, error) {
	mutex.Lock()
	defer mutex.Unlock()
	return argon2.Verify(ctx.a2ctx, hash, password, salt)
}

// VerifyEncoded verifies an encoded Argon2 hash s against a plaintext password.
// It mutates the context to match the encoding so unwise to use the same context for encoding and verifying
func (ctx *Context) VerifyEncoded(s string, password []byte) (bool, error) {
	hash, salt, err := ctx.SetFromEncoded(s)
	if err != nil {
		return false, err
	}
	return ctx.Verify(hash, password, salt)
}

func (ctx *Context) SetSecrets(password []byte, initialsalt []byte, ssa ...safesecrets.SecretSetter) (err error){
	if len(ssa) >= 1 {
		for i := 0; i < len(ssa); i++ {
			hash, err := ctx.Hash(password, initialsalt)
			if err != nil {
				return err;
			}
			ssa[i].SetSecret(hash)

			initialsalt = hash
		}
	}
	return nil
}
