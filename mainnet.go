// +build !testnet

package boltz

import "github.com/btcsuite/btcd/chaincfg"

const (
	apiURL = "https://boltz.exchange/api"
)

var (
	chain = &chaincfg.MainNetParams
)
