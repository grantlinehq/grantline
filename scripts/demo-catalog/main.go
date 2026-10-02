package main

import (
	"flag"
	"fmt"
	"github.com/grantlinehq/grantline/internal/demolab"
	"os"
	"time"
)

func main() {
	out := flag.String("out", "bin/demo-catalog", "optional demo artifact output directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "no positional arguments supported")
		os.Exit(1)
	}
	if err := demolab.Write(*out, time.Now().UTC().Truncate(time.Second)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Demo artifacts written to", *out)
}
