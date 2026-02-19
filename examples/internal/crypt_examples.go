package internal

import (
	"fmt"
	"os"

	"github.com/engmtcdrm/go-entomb/crypt"
)

func CryptExample() {
	crypt2, err := crypt.NewCrypt("___keyPath", "___tombsPath", true, true)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tombs := crypt2.Epitaph()
	for _, tomb := range tombs {
		fmt.Println("Tomb:")
		fmt.Println("  Name:", tomb.Name())
		fmt.Println("  Path:", tomb.Path())
		fmt.Println()
	}

	err = crypt2.Entomb("tomb1", []byte("This is a secret message"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = crypt2.Entomb("subdir/tomb1", []byte("This is a secret message"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = crypt2.Entomb("subdir2/subsubdir/tomb1", []byte("This is a secret message"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = crypt2.Entomb("tomb2.", []byte("This is a secret message"))
	if err != nil {
		fmt.Println(err)
	}

	tomb, err := crypt2.Exhume("tomb1")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Tomb value:", string(tomb))
	fmt.Println()

	// if err := crypt2.DesecrateAll(); err != nil {
	// 	panic(err)
	// }

	// fmt.Println("All tombs desecrated")

	tombs = crypt2.Epitaph()
	for _, tomb := range tombs {
		fmt.Println("Tomb:")
		fmt.Println("  Name:", tomb.Name())
		fmt.Println("  Path:", tomb.Path())
		fmt.Println()
	}
}
