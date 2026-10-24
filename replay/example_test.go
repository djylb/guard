package replay_test

import (
	"errors"
	"fmt"
	"time"

	"github.com/djylb/guard/replay"
)

func Example() {
	w, err := replay.New(replay.Config{Window: 30 * time.Second, Skew: 5 * time.Second})
	if err != nil {
		panic(err)
	}
	sent := time.Now()
	nonce := []byte("a random nonce, authenticated by the caller")

	fmt.Println(w.Check(sent, nonce))
	err = w.Check(sent, nonce)
	fmt.Println(errors.Is(err, replay.ErrReplay))
	// Output:
	// <nil>
	// true
}
