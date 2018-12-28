package main

import (
	"bytes"
	// "encoding/hex"
	"encoding/binary"
	// "encoding/json"
	"log"
	// "os"
	"github.com/bytom/common"
	"github.com/bytom/consensus"
	"github.com/bytom/crypto"
	"github.com/bytom/crypto/ed25519/chainkd"
	"github.com/bytom/errors"
	mnem "github.com/bytom/wallet/mnemonic"
	"strings"
)

const EntropyLength = 128

var (
	ErrMnemonicLength = errors.New("mnemonic length error")

	netParams = &consensus.MainNetParams

	mnemonic = "about about about about about about about about about about about about"
)

func main() {
	xprv, err := importKeyFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("root XPub:", xprv.XPub())

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

func genAddress(xPub chainkd.XPub, accountIdx uint64, addressIdx uint64) (string, error) {
	path := pathForAddress(accountIdx, addressIdx)
	derivedXPub := xPub.Derive(path)
	derivedPK := derivedXPub.PublicKey()
	pubHash := crypto.Ripemd160(derivedPK)

	address, err := common.NewAddressWitnessPubKeyHash(pubHash, netParams)
	if err != nil {
		return "", errors.Wrap(err, "NewAddressWitnessPubKeyHash")
	}

	return address.EncodeAddress(), nil
}

func pathForAddress(accountIdx, addressIndex uint64) [][]byte {
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
