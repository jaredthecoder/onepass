package main

import (
    "fmt"
    "strings"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/ssh/terminal"
    "github.com/fatih/color"
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

func main() {
    // Random salt to be used in key derivation
    salt := "45U1OI6RJP0NWIA8L1PQ6JL6EC7"
    var accountName string

    // Header to be printed when the program runs
    header := "  ___           ___            \n / _ \\ _ _  ___| _ \\__ _ ______\n| (_) | ' \\/ -_)  _/ _` (_-<_-<\n \\___/|_||_\\___|_| \\__,_/__/__/\n"

    //ANSI Colors
    cyan := color.New(color.FgCyan).SprintFunc()
    green := color.New(color.FgGreen).SprintFunc()
    red := color.New(color.FgRed).SprintFunc()

    fmt.Printf("\n\n%s", cyan(header))
    fmt.Printf("\n\nWritten by: %s\n", red("Jared Smith"))

    // Read master password from stdin
    fmt.Printf("\n\nEnter your %s: ", cyan("master password"))
    masterPassword, err := terminal.ReadPassword(0)
    if err != nil {
        panic(err)
    }

    // Read account name from stdin
    fmt.Printf("\nEnter the %s corresponding to the password you want to retrieve: ", cyan("account name"))
    fmt.Scanln(&accountName)
    for (accountName == "\n" || accountName == "") {
        fmt.Printf("\n%s\n", red("Your account name can't be blank. Try again!"))
        fmt.Printf("\nEnter the %s corresponding to the password you want to retrieve: ", cyan("account name"))
        fmt.Scanln(&accountName)
    }

    // Strip newline from the account name
    accountNameStripped := strings.TrimSpace(accountName)

    // Calculate the password based on the master password and account name
    password := CalculatePassword(accountNameStripped, string(masterPassword), salt)
    fmt.Printf("\n\nYour %s for %s is: %s\n", cyan("password"), cyan(accountNameStripped), green(password))
}
