package argon2_go_withsecret

import (
	"crypto/rand"
	"testing"
)

var password = make([]byte, 32)
var salt = make([]byte, 32)

func init() {
	_, err := rand.Read(password)
	if err != nil {
		panic(err)
	}
	_, err = rand.Read(salt)
	if err != nil {
		panic(err)
	}
}

func BenchmarkHash_i_m12_p1(b *testing.B) { benchmarkHash(b, ModeArgon2i, 12, 1) } // 4 MiB
func BenchmarkHash_i_m12_p2(b *testing.B) { benchmarkHash(b, ModeArgon2i, 12, 2) }
func BenchmarkHash_i_m12_p4(b *testing.B) { benchmarkHash(b, ModeArgon2i, 12, 4) }
func BenchmarkHash_i_m15_p1(b *testing.B) { benchmarkHash(b, ModeArgon2i, 15, 1) } // 32 MiB
func BenchmarkHash_i_m15_p2(b *testing.B) { benchmarkHash(b, ModeArgon2i, 15, 2) }
func BenchmarkHash_i_m15_p4(b *testing.B) { benchmarkHash(b, ModeArgon2i, 15, 4) }
func BenchmarkHash_i_m18_p1(b *testing.B) { benchmarkHash(b, ModeArgon2i, 18, 1) } // 256 MiB
func BenchmarkHash_i_m18_p2(b *testing.B) { benchmarkHash(b, ModeArgon2i, 18, 2) }
func BenchmarkHash_i_m18_p4(b *testing.B) { benchmarkHash(b, ModeArgon2i, 18, 4) }
func BenchmarkHash_i_m19_p1(b *testing.B) { benchmarkHash(b, ModeArgon2i, 19, 1) } // 512 MiB
func BenchmarkHash_i_m19_p2(b *testing.B) { benchmarkHash(b, ModeArgon2i, 19, 2) }
func BenchmarkHash_i_m19_p4(b *testing.B) { benchmarkHash(b, ModeArgon2i, 19, 4) }

func BenchmarkHash_d_m12_p1(b *testing.B) { benchmarkHash(b, ModeArgon2d, 12, 1) } // 4 MiB
func BenchmarkHash_d_m12_p2(b *testing.B) { benchmarkHash(b, ModeArgon2d, 12, 2) }
func BenchmarkHash_d_m12_p4(b *testing.B) { benchmarkHash(b, ModeArgon2d, 12, 4) }
func BenchmarkHash_d_m15_p1(b *testing.B) { benchmarkHash(b, ModeArgon2d, 15, 1) } // 32 MiB
func BenchmarkHash_d_m15_p2(b *testing.B) { benchmarkHash(b, ModeArgon2d, 15, 2) }
func BenchmarkHash_d_m15_p4(b *testing.B) { benchmarkHash(b, ModeArgon2d, 15, 4) }
func BenchmarkHash_d_m18_p1(b *testing.B) { benchmarkHash(b, ModeArgon2d, 18, 1) } // 256 MiB
func BenchmarkHash_d_m18_p2(b *testing.B) { benchmarkHash(b, ModeArgon2d, 18, 2) }
func BenchmarkHash_d_m18_p4(b *testing.B) { benchmarkHash(b, ModeArgon2d, 18, 4) }
func BenchmarkHash_d_m20_p1(b *testing.B) { benchmarkHash(b, ModeArgon2d, 20, 1) } // 1024 MiB
func BenchmarkHash_d_m20_p2(b *testing.B) { benchmarkHash(b, ModeArgon2d, 20, 2) }
func BenchmarkHash_d_m20_p4(b *testing.B) { benchmarkHash(b, ModeArgon2d, 20, 4) }

func BenchmarkHash_id_m12_p1(b *testing.B) { benchmarkHash(b, ModeArgon2id, 12, 1) } // 4 MiB
func BenchmarkHash_id_m12_p2(b *testing.B) { benchmarkHash(b, ModeArgon2id, 12, 2) }
func BenchmarkHash_id_m12_p4(b *testing.B) { benchmarkHash(b, ModeArgon2id, 12, 4) }
func BenchmarkHash_id_m15_p1(b *testing.B) { benchmarkHash(b, ModeArgon2id, 15, 1) } // 32 MiB
func BenchmarkHash_id_m15_p2(b *testing.B) { benchmarkHash(b, ModeArgon2id, 15, 2) }
func BenchmarkHash_id_m15_p4(b *testing.B) { benchmarkHash(b, ModeArgon2id, 15, 4) }
func BenchmarkHash_id_m18_p1(b *testing.B) { benchmarkHash(b, ModeArgon2id, 18, 1) } // 256 MiB
func BenchmarkHash_id_m18_p2(b *testing.B) { benchmarkHash(b, ModeArgon2id, 18, 2) }
func BenchmarkHash_id_m18_p4(b *testing.B) { benchmarkHash(b, ModeArgon2id, 18, 4) }
func BenchmarkHash_id_m19_p1(b *testing.B) { benchmarkHash(b, ModeArgon2id, 19, 1) } // 512 MiB
func BenchmarkHash_id_m19_p2(b *testing.B) { benchmarkHash(b, ModeArgon2id, 19, 2) }
func BenchmarkHash_id_m19_p4(b *testing.B) { benchmarkHash(b, ModeArgon2id, 19, 4) }
func BenchmarkHash_id_m21_p1(b *testing.B) { benchmarkHash(b, ModeArgon2id, 21, 1) } // 2048 MiB
func BenchmarkHash_id_m21_p2(b *testing.B) { benchmarkHash(b, ModeArgon2id, 21, 2) }
func BenchmarkHash_id_m21_p4(b *testing.B) { benchmarkHash(b, ModeArgon2id, 21, 4) }

func benchmarkHash(b *testing.B, mode, memory, parallelism int) {
    ctx := NewContext(mode)
    ctx.SetMemory(1 << uint(memory))
    ctx.SetParallelism(parallelism)

	b.SetBytes(int64(ctx.GetMemory()) << 10)

	for n := 0; n < b.N; n++ {
		if _, err := ctx.Hash( password, salt); err != nil {
			b.Error(err)
		}
	}
}
