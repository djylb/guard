package pow_test

import (
	"context"
	"fmt"

	"github.com/djylb/guard/pow"
)

func Example() {
	// Servers that verify each other's challenges share a key; nil
	// generates one for this process.
	c, err := pow.New(pow.Config{Difficulty: 10})
	if err != nil {
		panic(err)
	}
	// Bind the challenge to what it protects, such as the client's IP
	// address and the form.
	binding := []byte("198.51.100.4|login")
	token, err := c.Issue(binding)
	if err != nil {
		panic(err)
	}

	// The client does the work.
	solution, err := pow.Solve(context.Background(), token)
	if err != nil {
		panic(err)
	}

	fmt.Println(c.Verify(token, solution, binding))
	fmt.Println(c.Verify(token, solution, binding))
	// Output:
	// <nil>
	// pow: challenge already used
}
