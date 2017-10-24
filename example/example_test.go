package example

import (
	"testing"
	"time"
	"log"
)

func TestExample(t *testing.T) {
	log.Printf("time= %v\n", time.Now())
	ts := time.Now().Unix()
	for i := 0; i < 50; i++ {
		example1()
	}
	ts2 := time.Now().Unix()
	tdiff := ts2-ts
	log.Printf("50 ops in %v seconds\n", tdiff)



	log.Printf("time= %v\n", time.Now())

	for i := 0; i < 6; i++ {
		 example2()
	}
	log.Printf("time= %v\n", time.Now())


	for i := 0; i < 6; i++ {
		 example3()
	}

	log.Printf("time= %v\n", time.Now())

	for i := 0; i < 6; i++ {
		go example2()
	}
	log.Printf("launched 6 go routines time= %v\n", time.Now())


	time.Sleep(time.Second * 30)
}

