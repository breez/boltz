//go:build testnet
// +build testnet

package boltz

import "github.com/btcsuite/btcd/chaincfg"

const (
	apiURL = "https://testnet.boltz.exchange/api"
)

var (
	chain = &chaincfg.TestNet3Params
)
