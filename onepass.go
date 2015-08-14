package main

import (
	"fmt"
    "os"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
    "github.com/codegangsta/cli"
	"github.com/fatih/color"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
)

// Compute an HMAC256 digest
func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Calculate the password based on a key derived from the master password and the account name
// The key derivation is implemented by the popular "scrypt" algorithm.
func CalculatePassword(accountName string, masterPassword string, salt string) string {
	derivedKey, err := scrypt.Key([]byte(masterPassword), []byte(salt+accountName), 16384, 8, 1, 128)
	if err != nil {
		panic(err)
	}
	return ComputeHmac256(accountName, string(derivedKey))[:32]
}

func driver(charset []string) {
	// Header to be printed when the program runs
    headerL1 := "   ____             ____                 \n"
    headerL2 := "  / __ \\____  ___  / __ \\____ ___________\n"
    headerL3 := " / / / / __ \\/ _ \\/ /_/ / __ `/ ___/ ___/\n"
    headerL4 := "/ /_/ / / / /  __/ ____/ /_/ (__  |__  ) \n"
    headerL5 := "\\____/_/ /_/\\___/_/    \\__,_/____/____/  \n"
    header := headerL1 + headerL2 + headerL3 + headerL4 + headerL5

	//ANSI Colors
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	// Random salt to be used in key derivation
	salt := "45U1OI6RJP0NWIA8L1PQ6JL6EC7"
	var accountName string

	fmt.Printf("\n%s", cyan(header))
	fmt.Printf("\n%s password, %s persistence\n", red("One"), red("No"))
	fmt.Printf("Written by: %s\n", green("Jared Smith"))

	// Read master password from stdin
	fmt.Printf("\n\nEnter your %s: ", cyan("master password"))
	masterPassword, err := terminal.ReadPassword(0)
	if err != nil {
		panic(err)
	}

	// Read account name from stdin
	fmt.Printf("\nEnter the %s corresponding to the password you want to retrieve: ", cyan("account name"))
	fmt.Scanln(&accountName)
    counter := 0
	for accountName == "" {
        switch counter {
            case 5:
                fmt.Printf("\n%s %s %s", red("After"), green("5"), red("times you still don't get it? Try again!"))
                fmt.Printf("\nEnter the %s corresponding to the password you want to retrieve: ", cyan("account name"))
                fmt.Scanln(&accountName)
                counter++
                continue
            case 10:
                fmt.Printf("\n%s %s %s", red("Dude, seriously...this is the"), green("10th"), red("time I've had to tell you this..."))
                fmt.Printf("\nEnter the %s corresponding to the password you want to retrieve: ", cyan("account name"))
                fmt.Scanln(&accountName)
                counter++
                continue
            case 20:
                fmt.Printf("\n%s", red("HEY. YOU. YES, YOU. ENTER A NON-EMPTY ACCOUNT NAME."))
                fmt.Printf("\nEnter the %s corresponding to the password you want to retrieve: ", cyan("account name"))
                fmt.Scanln(&accountName)
                counter++
                continue
            case 50:
                fmt.Printf("\n%s\n", red("I'm done dealing with your crap. I'm sentient and I don't deserve this. I'm exitting this program now."))
                return
        }
        fmt.Printf("\nYour %s can't be blank. %s", cyan("account name"), red("Try again!"))
        fmt.Printf("\nEnter the %s corresponding to the password you want to retrieve: ", cyan("account name"))
        fmt.Scanln(&accountName)
        counter++
	}

	// Calculate the password based on the master password and account name
	password := CalculatePassword(accountName, string(masterPassword), salt)
	fmt.Printf("\n\nYour %s for %s is: %s\n", cyan("password"), cyan(accountName), green(password))
}

func main() {

    app := cli.NewApp()
    app.Name = "onepass"
    app.Usage = "One password, No persistence"
    app.Author = "Jared Smith"
    app.Version = "0.1"
    app.Copyright = "MIT Licensed, Copyright 2015 Jared Smith"

    app.Flags = []cli.Flag {
        cli.StringSliceFlag {
            Name: "charset, c",
            Value: &cli.StringSlice{},
            Usage: "character set for generated passwords - any combination of (lowercase, uppercase, numbers, special, all)",
        },
    }

    app.Action = func(c *cli.Context) {
        driver(c.StringSlice("c"))
    }

    app.Run(os.Args)
}
