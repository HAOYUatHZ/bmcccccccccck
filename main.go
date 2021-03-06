package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/bytom/common"
	"github.com/bytom/consensus"
	"github.com/bytom/crypto"
	"github.com/bytom/crypto/ed25519/chainkd"
	"github.com/bytom/errors"
	mnem "github.com/bytom/wallet/mnemonic"
	"github.com/bytom/wallet/mnemonic/wordlists"
)

const EntropyLength = 128

var (
	ErrMnemonicLength = errors.New("mnemonic length error")

	netParams = &consensus.MainNetParams
)

func main() {
	indexes := [12]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

REDO:
	indexes = incr(indexes)
	words := make([]string, 12)
	for i := 0; i < 12; i++ {
		words[i] = wordlists.English[indexes[i]]

	}
	mnemonic := strings.Join(words, " ")
	log.Printf("Trying %v \"%s\"...", indexes, mnemonic)
	if addr, err := validate(mnemonic); err == nil {
		log.Printf("Find valid address %s with \"%s\"...", addr, mnemonic)
	}

	goto REDO
}

func validate(mnemonic string) (string, error) {
	xprv, err := importKeyFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}

	path := genPath(1, 1)
	address, err := genAddress(xprv.Derive(path).XPub())
	if err != nil {
		return "", err
	}

	balance, err := getBalance(address)
	if err != nil {
		return "", err
	}

	if balance <= 0 {
		return "", errors.New("poor guy")
	}

	return address, nil
}

func importKeyFromMnemonic(mnemonic string) (*chainkd.XPrv, error) {
	// checksum length = entropy length /32
	// mnemonic length = (entropy length + checksum length)/11
	if len(strings.Fields(mnemonic)) != (EntropyLength+EntropyLength/32)/11 {
		return nil, ErrMnemonicLength
	}

	// Pre validate that the mnemonic is well formed and only contains words that
	// are present in the word list
	if !mnem.IsMnemonicValid(mnemonic, "en") {
		return nil, mnem.ErrInvalidMnemonic
	}

	return createKeyFromMnemonic(mnemonic)
}

func createKeyFromMnemonic(mnemonic string) (*chainkd.XPrv, error) {
	seed := mnem.NewSeed(mnemonic, "")
	xprv, err := chainkd.NewXPrv(bytes.NewBuffer(seed))
	if err != nil {
		return nil, err
	}

	return &xprv, nil
}

func genAddress(derivedXPub chainkd.XPub) (string, error) {
	derivedPK := derivedXPub.PublicKey()
	pubHash := crypto.Ripemd160(derivedPK)

	address, err := common.NewAddressWitnessPubKeyHash(pubHash, netParams)
	if err != nil {
		return "", errors.Wrap(err, "NewAddressWitnessPubKeyHash")
	}

	return address.EncodeAddress(), nil
}

func genPath(accountIdx, addressIndex uint64) [][]byte {
	/*
	   path is follow by bip44 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
	   path[0] and path[1] is bip44 hard code rule
	   path[2] is the account index
	   path[3] is the change index, but it's always 0 in the blockcenter case
	   path[4] is the address index
	*/
	path := [][]byte{
		[]byte{0x2C, 0x00, 0x00, 0x00},
		[]byte{0x99, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00},
	}
	binary.LittleEndian.PutUint32(path[2], uint32(accountIdx))
	binary.LittleEndian.PutUint32(path[4], uint32(addressIndex))
	return path
}

type addressDetail struct {
	Balance uint64 `json:"balance"`
}

func getBalance(address string) (uint64, error) {
	url := "https://blockmeta.com/api/v2/address/" + address
	var resp addressDetail
	if err := httpGet(url, &resp); err != nil {
		return 0, err
	}

	return resp.Balance, nil
}

func httpGet(url string, result interface{}) error {
	client := &http.Client{}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, result)
}

func incr(indexes [12]uint64) [12]uint64 {
	indexes[11]++

	for i := 11; i >= 0; i-- {
		// log.Println(indexes)
		if (indexes[i] >= 2048) && (i-1) >= 0 {
			indexes[i-1]++
			for j := i; j <= 11; j++ {
				indexes[j] = 0
			}
		}
	}

	if indexes[0] >= 2048 {
		log.Fatal("Done")
	}

	return indexes
}
