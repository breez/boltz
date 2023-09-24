// +build !testnet

package boltz

import "github.com/btcsuite/btcd/chaincfg"

const (
	apiURL = "https://api.boltz.exchange"
)

var (
	chain = &chaincfg.MainNetParams
)
