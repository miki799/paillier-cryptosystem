package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
)

type PublicKey struct {
	n *big.Int
	g *big.Int
}

type PrivateKey struct {
	lambda *big.Int
	u      *big.Int
}

var logger = log.New(os.Stdout, "", 0)

var ZERO *big.Int = big.NewInt(0)
var ONE *big.Int = big.NewInt(1)
var TWO *big.Int = big.NewInt(2)

/*
Generates PublicKey{n, g} and PrivateKey{lambda, u}
*/
func generateKeys(bits int) (*PrivateKey, *PublicKey) {
	logger.Printf("Generating %v bits keys...\n", bits)

	p, q := generatePrimes(bits)
	n := new(big.Int).Mul(p, q)

	/*
		simplified version,
		because p and q bit length is equal
	*/

	// lambda = fi(n) = (p-1)(q-1)
	lambda := new(big.Int).Mul(
		new(big.Int).Sub(p, ONE),
		new(big.Int).Sub(q, ONE))
	// g = n + 1
	g := new(big.Int).Add(n, ONE)
	// u = fi(n)^-1(modn)
	u := new(big.Int).ModInverse(lambda, n)

	return &PrivateKey{lambda, u}, &PublicKey{n, g}
}

/*
Encrypts message
*/
func encrypt(publicKey *PublicKey, message *big.Int) (*big.Int, error) {
	logger.Println("Message encryption...")

	// Check if message fullfils 0 <= message < n
	if message.Cmp(ZERO) == -1 || message.Cmp(publicKey.n) > -1 {
		return nil, fmt.Errorf("message is out of allowed range")
	}

	square := calculateNSquare(publicKey.n)
	r := generateRandomR(publicKey.n)
	c1 := new(big.Int).Exp(publicKey.g, message, square)
	c2 := new(big.Int).Exp(r, publicKey.n, square)
	ciphertext := new(big.Int).Mul(c1, c2)
	ciphertext.Mod(ciphertext, square)

	return ciphertext, nil
}

/*
Decrypts ciphertext
*/
func decrypt(privateKey *PrivateKey, ciphertext, n *big.Int) *big.Int {
	logger.Println("Message decryption...")

	decipheredMessage := new(big.Int).Exp(ciphertext, privateKey.lambda, calculateNSquare(n))
	L(decipheredMessage, n)
	decipheredMessage.Mul(decipheredMessage, privateKey.u)
	decipheredMessage.Mod(decipheredMessage, n)

	return decipheredMessage
}

/*
Generates randomly two large prime numbers p and q,
such that gcd(pq,(p-1)*(q-1)) == 1
*/
func generatePrimes(bits int) (*big.Int, *big.Int) {
	logger.Println("Generating two large prime numbers p and q...")
	p, q, isPrime := new(big.Int), new(big.Int), true
	var err1, err2 error = nil, nil

	for {
		p, err1 = rand.Prime(rand.Reader, bits)
		logger.Println("Checking if generated p is really a prime number...")
		isPrime = p.ProbablyPrime(bits)

		if err1 != nil || !isPrime {
			logger.Printf("generatePrime: err1 = %v, isPrime = %v", err1, isPrime)
		}

		q, err2 = rand.Prime(rand.Reader, bits)
		logger.Println("Checking if generated q is really a prime number...")
		isPrime = q.ProbablyPrime(bits)

		if err2 != nil || !isPrime {
			logger.Printf("generatePrime: err2 = %v, isPrime = %v", err2, isPrime)
		}

		// check if gcd == 1
		if checkGCD(p, q) {
			break
		}

		logger.Println("GCD is not equal 1! Retrying...")
	}

	return p, q
}

/*
Checks if gcd(pq,(p-1)*(q-1)) == 1
*/
func checkGCD(p, q *big.Int) bool {
	n := new(big.Int).Mul(p, q)
	gcd := new(big.Int).GCD(
		nil, nil, n,
		new(big.Int).Mul(
			new(big.Int).Sub(p, ONE),
			new(big.Int).Sub(q, ONE)))

	return gcd.Cmp(ONE) == 0
}

/*
Calculates n^2
*/
func calculateNSquare(n *big.Int) *big.Int {
	return new(big.Int).Exp(n, TWO, nil)
}

/*
Generates random R n^2, where 0 < r < n
and gcd(r, n) == 1
*/
func generateRandomR(n *big.Int) *big.Int {
	g, gcd := new(big.Int), new(big.Int)
	var err error = nil

	for {
		g, err = rand.Int(rand.Reader, n)
		if err != nil {
			logger.Printf("generateRandomR: err = %v", err)
		}

		if gcd.GCD(nil, nil, g, n).Cmp(ONE) == 0 {
			break
		}
	}

	return g
}

/*
Calculates l(x) = x - 1 / n
*/
func L(x, n *big.Int) {
	x.Div(x.Sub(x, ONE), n)
}

func addCiphertexts(ciphertext1, ciphertext2, n *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(ciphertext1, ciphertext2), calculateNSquare(n))
}

func multiplyCiphertext(ciphertext, num, n *big.Int) *big.Int {
	return new(big.Int).Exp(ciphertext, num, calculateNSquare(n))
}

func main() {
	bits := 2048
	privateKey, publicKey := generateKeys(bits)

	/*
		Encrypt two plaintexts
	*/

	logger.Printf("\n## Encrypt two plaintexts ##")

	message1 := big.NewInt(1234)
	logger.Printf("Message to encrypt: %v\n", message1)

	ciphertext1, err1 := encrypt(publicKey, message1)

	if err1 != nil {
		logger.Println(err1.Error())
		return
	}

	//logger.Printf("ciphertext: %v\n", ciphertext1)

	decipheredMessage1 := decrypt(privateKey, ciphertext1, publicKey.n)
	logger.Printf("Decrypted message: %v\n", decipheredMessage1)

	message2 := big.NewInt(222)
	logger.Printf("Message to encrypt: %v\n", message2)

	ciphertext2, err2 := encrypt(publicKey, message2)

	if err2 != nil {
		logger.Println(err2.Error())
		return
	}

	//logger.Printf("ciphertext: %v\n", ciphertext2)

	decipheredMessage2 := decrypt(privateKey, ciphertext2, publicKey.n)
	logger.Printf("Decrypted message: %v\n\n", decipheredMessage2)

	/*
		Addition of two ciphertexts
	*/

	logger.Printf("## Addition of two ciphertexts ##")

	expectedResult := new(big.Int).Add(message1, message2)
	ciphertextsSum := addCiphertexts(ciphertext1, ciphertext2, publicKey.n)
	decryptedResult := decrypt(privateKey, ciphertextsSum, publicKey.n)

	if decryptedResult.Cmp(expectedResult) == 0 {
		logger.Printf("C(%v) + C(%v) = C(%v)\n\n", message1, message2, decryptedResult)
	} else {
		logger.Println("Addition went wrong!")
	}

	/*
		Multiplication of a ciphertext by a plaintext number
	*/

	logger.Printf("## Multiplication of a ciphertext by a plaintext number ##")

	expectedResult = new(big.Int).Mul(message1, TWO)
	multipliedCiphertext := multiplyCiphertext(ciphertext1, TWO, publicKey.n)
	decryptedResult = decrypt(privateKey, multipliedCiphertext, publicKey.n)

	if decryptedResult.Cmp(expectedResult) == 0 {
		logger.Printf("C(%v) * %v = C(%v)\n", message1, TWO, decryptedResult)
	} else {
		logger.Println("Multiplication went wrong!")
	}
}
