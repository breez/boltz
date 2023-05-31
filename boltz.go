package boltz

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/zpay32"
)

const (
	getNodesEndpoint             = "/getnodes"
	getPairsEndpoint             = "/getpairs"
	createSwapEndpoint           = "/createswap"
	routingHintsEndpoint         = "/routinghints"
	swapStatusEndpoint           = "/swapstatus"
	broadcastTransactionEndpoint = "/broadcasttransaction"
	claimWitnessInputSize        = 1 + 1 + 8 + 73 + 1 + 32 + 1 + 100
)

var ErrSwapNotFound = errors.New("transaction not in mempool or settled/canceled")

type BadRequestError string

func (e *BadRequestError) Error() string {
	return string(*e)
}

type boltzReverseSwap struct {
	ID                 string `json:"id"`
	Invoice            string `json:"invoice"`
	RedeemScript       string `json:"redeemScript"`
	LockupAddress      string `json:"lockupAddress"`
	OnchainAmount      int64  `json:"onchainAmount"`
	TimeoutBlockHeight int64  `json:"timeoutBlockHeight"`
}

type ReverseSwap struct {
	boltzReverseSwap
	Preimage string
	Key      string
}

type ReverseSwapInfo struct {
	FeesHash string
	Max      int64
	Min      int64
	Fees     struct {
		Percentage float64
		Lockup     int64
		Claim      int64
	}
}

type RoutingHint struct {
	HopHintsList []struct {
		NodeID                    string `json:"nodeId"`
		ChanID                    string `json:"chanId"`
		FeeBaseMsat               uint32 `json:"feeBaseMsat"`
		FeeProportionalMillionths uint32 `json:"feeProportionalMillionths"`
		CltvExpiryDelta           uint32 `json:"cltvExpiryDelta"`
	} `json:"hopHintsList"`
}

func GetReverseSwapInfo() (*ReverseSwapInfo, error) {
	resp, err := http.Get(apiURL + getPairsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("getpairs get %v: %w", apiURL+getPairsEndpoint, err)
	}
	defer resp.Body.Close()

	var pairs struct {
		Warnings []string `json:"warnings"`
		Pairs    map[string]struct {
			Rate   float64 `json:"rate"`
			Hash   string  `json:"hash"`
			Limits struct {
				Maximal         int64 `json:"maximal"`
				Minimal         int64 `json:"minimal"`
				MaximalZeroConf struct {
					BaseAsset  int64 `json:"baseAsset"`
					QuoteAsset int64 `json:"quoteAsset"`
				} `json:"maximalZeroConf"`
			}
			Fees struct {
				Percentage float64 `json:"percentage"`
				MinerFees  struct {
					BaseAsset struct {
						Normal  int64 `json:"normal"`
						Reverse struct {
							Lockup int64 `json:"lockup"`
							Claim  int64 `json:"claim"`
						} `json:"reverse"`
					} `json:"baseAsset"`
					QuoteAsset struct {
						Normal  int64 `json:"normal"`
						Reverse struct {
							Lockup int64 `json:"lockup"`
							Claim  int64 `json:"claim"`
						} `json:"reverse"`
					} `json:"quoteAsset"`
				} `json:"minerFees"`
			} `json:"fees"`
		} `json:"pairs"`
	}
	err = json.NewDecoder(resp.Body).Decode(&pairs)
	if err != nil {
		return nil, fmt.Errorf("json decode (status: %v): %w", resp.Status, err)
	}
	for _, w := range pairs.Warnings {
		if w == "reverse.swaps.disabled" {
			return nil, fmt.Errorf("reverse.swaps.disabled")
		}
	}
	btcPair, ok := pairs.Pairs["BTC/BTC"]
	if !ok {
		return nil, fmt.Errorf("no BTC/BTC pair")
	}
	return &ReverseSwapInfo{
		FeesHash: btcPair.Hash,
		Max:      btcPair.Limits.Maximal,
		Min:      btcPair.Limits.Minimal,
		Fees: struct {
			Percentage float64
			Lockup     int64
			Claim      int64
		}{
			Percentage: btcPair.Fees.Percentage,
			Lockup:     btcPair.Fees.MinerFees.BaseAsset.Reverse.Lockup,
			Claim:      btcPair.Fees.MinerFees.BaseAsset.Reverse.Claim,
		},
	}, nil
}

func GetRoutingHints(routingNode []byte) ([]RoutingHint, error) {
	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(struct {
		Symbol      string `json:"symbol"`
		RoutingNode string `json:"routingNode"`
	}{
		Symbol:      "BTC",
		RoutingNode: hex.EncodeToString(routingNode),
	})
	if err != nil {
		return nil, fmt.Errorf("json encode %x: %w", routingNode, err)
	}
	resp, err := http.Post(apiURL+routingHintsEndpoint, "application/json", buffer)
	if err != nil {
		//log.Printf("routinghints post %v: %v", apiURL+routingHintsEndpoint, err)
		return nil, fmt.Errorf("routinghints post %v: %w", apiURL+routingHintsEndpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		e := struct {
			Error string `json:"error"`
		}{}
		err = json.NewDecoder(resp.Body).Decode(&e)
		if err != nil {
			return nil, fmt.Errorf("json decode (status: %v): %w", resp.Status, err)
		}
		badRequestError := BadRequestError(e.Error)
		//log.Printf("routinghints result (status: %v) %v", resp.Status, &badRequestError)
		return nil, fmt.Errorf("routinghints result (status: %v) %w", resp.Status, &badRequestError)
	}

	var boltzHints struct {
		RoutingHints []RoutingHint `json:"routingHints"`
	}
	err = json.NewDecoder(resp.Body).Decode(&boltzHints)
	if err != nil {
		return nil, fmt.Errorf("json decode (status ok): %w", err)
	}

	return boltzHints.RoutingHints, nil
}

func createReverseSwap(amt int64, feesHash string, preimage []byte, key *btcec.PrivateKey, routingNode []byte) (*boltzReverseSwap, error) {
	h := sha256.Sum256(preimage)
	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(struct {
		Type           string `json:"type"`
		PairID         string `json:"pairId"`
		OrderSide      string `json:"orderSide"`
		InvoiceAmount  int64  `json:"invoiceAmount"`
		PreimageHash   string `json:"preimageHash"`
		PairHash       string `json:"pairHash,omitempty"`
		ClaimPublicKey string `json:"claimPublicKey"`
		RoutingNode    string `json:"routingNode,omitempty"`
	}{
		Type:           "reversesubmarine",
		PairID:         "BTC/BTC",
		OrderSide:      "buy",
		InvoiceAmount:  amt,
		PreimageHash:   hex.EncodeToString(h[:]),
		PairHash:       feesHash,
		ClaimPublicKey: hex.EncodeToString(txscript.ComputeTaprootKeyNoScript(key.PubKey()).SerializeCompressed()),
		RoutingNode:    hex.EncodeToString(routingNode),
	})
	if err != nil {
		return nil, fmt.Errorf("json encode %v, %v, %v: %w", amt, preimage, key, err)
	}

	resp, err := http.Post(apiURL+createSwapEndpoint, "application/json", buffer)
	if err != nil {
		return nil, fmt.Errorf("createswap post %v: %w", apiURL+createSwapEndpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		e := struct {
			Error string `json:"error"`
		}{}
		err = json.NewDecoder(resp.Body).Decode(&e)
		if err != nil {
			return nil, fmt.Errorf("json decode (status: %v): %w", resp.Status, err)
		}
		badRequestError := BadRequestError(e.Error)
		return nil, fmt.Errorf("createswap result (status: %v) %w", resp.Status, &badRequestError)
	}

	var rs boltzReverseSwap
	err = json.NewDecoder(resp.Body).Decode(&rs)
	if err != nil {
		return nil, fmt.Errorf("json decode (status ok): %w", err)
	}

	return &rs, nil
}

func checkHeight(h int64, hs string) string {
	b1, err := hex.DecodeString(hs)
	if err != nil {
		return ""
	}
	b := make([]byte, 8)
	copy(b, b1)
	if binary.LittleEndian.Uint64(b) == uint64(h) {
		return hs
	}
	return ""
}

func checkReverseSwap(amt btcutil.Amount, preimage []byte, key *btcec.PrivateKey, rs *boltzReverseSwap) error {
	script, err := hex.DecodeString(rs.RedeemScript)
	if err != nil {
		return fmt.Errorf("hex.DecodeString %v: %w", rs.RedeemScript, err)
	}
	dis, err := txscript.DisasmString(script)
	if err != nil {
		return fmt.Errorf("txscript.DisasmString %x: %w", script, err)
	}
	d := strings.Split(dis, " ")
	h := sha256.Sum256(preimage)

	s := fmt.Sprintf(
		"OP_SIZE 20 OP_EQUAL OP_IF OP_HASH160 %x OP_EQUALVERIFY %x OP_ELSE OP_DROP %s OP_CHECKLOCKTIMEVERIFY OP_DROP %s OP_ENDIF OP_CHECKSIG",
		input.Ripemd160H(h[:]),
		key.PubKey().SerializeCompressed(),
		checkHeight(rs.TimeoutBlockHeight, d[10]),
		d[13],
	)
	if s != dis {
		return fmt.Errorf("bad script")
	}
	a, err := addressWitnessScriptHash(script, chain)
	if err != nil {
		return fmt.Errorf("addressWitnessScriptHash %v: %w", script, err)
	}

	if rs.LockupAddress != a.String() {
		return fmt.Errorf("bad address: %v instead of %v", rs.LockupAddress, a.String())
	}

	rawInvoice, err := zpay32.Decode(rs.Invoice, chain)
	if err != nil {
		return fmt.Errorf("zpay32.Decode %v: %w", rs.Invoice, err)
	}

	if rawInvoice.MilliSat == nil {
		return fmt.Errorf("invoice does not contain an amount: %v", rs.Invoice)
	}

	actualAmt := *rawInvoice.MilliSat
	if uint64(amt)*1000 != uint64(actualAmt) {
		return fmt.Errorf("invoice amount mismatch. expected %v sat. %v", int64(amt), rs.Invoice)
	}

	if !bytes.Equal(h[:], rawInvoice.PaymentHash[:]) {
		return fmt.Errorf("invoice payment hash mismatch. expected %x. %v", h[:], rs.Invoice)
	}

	return nil
}

func addressWitnessScriptHash(script []byte, net *chaincfg.Params) (*btcutil.AddressWitnessScriptHash, error) {
	witnessProg := sha256.Sum256(script)
	return btcutil.NewAddressWitnessScriptHash(witnessProg[:], net)
}

func getPreimage() []byte {
	preimage := make([]byte, 32)
	rand.Read(preimage)
	return preimage
}

func getPrivate() (*btcec.PrivateKey, error) {
	k, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("btcec.NewPrivateKey: %w", err)
	}
	return k, nil
}

// NewReverseSwap begins the reverse submarine process.
func NewReverseSwap(amt btcutil.Amount, feesHash string, routingNode []byte) (*ReverseSwap, error) {
	preimage := getPreimage()

	key, err := getPrivate()
	if err != nil {
		return nil, fmt.Errorf("getPrivate: %w", err)
	}

	rs, err := createReverseSwap(int64(amt), feesHash, preimage, key, routingNode)
	if err != nil {
		return nil, fmt.Errorf("createReverseSwap amt:%v, preimage:%x, key:%x; %w", amt, preimage, key, err)
	}

	err = checkReverseSwap(amt, preimage, key, rs)
	if err != nil {
		return nil, fmt.Errorf("checkReverseSwap preimage:%x, key:%x, %#v; %w", preimage, key, rs, err)
	}

	return &ReverseSwap{*rs, hex.EncodeToString(preimage), hex.EncodeToString(key.Serialize())}, nil
}

// CheckTransaction checks that the transaction corresponds to the adresss and amount
func CheckTransaction(transactionHex, lockupAddress string, amt int64) (string, error) {
	txSerialized, err := hex.DecodeString(transactionHex)
	if err != nil {
		return "", fmt.Errorf("hex.DecodeString(%v): %w", transactionHex, err)
	}
	tx, err := btcutil.NewTxFromBytes(txSerialized)
	if err != nil {
		return "", fmt.Errorf("btcutil.NewTxFromBytes(%x): %w", txSerialized, err)
	}
	var out *wire.OutPoint
	for i, txout := range tx.MsgTx().TxOut {
		class, addresses, requiredsigs, err := txscript.ExtractPkScriptAddrs(txout.PkScript, chain)
		if err != nil {
			return "", fmt.Errorf("txscript.ExtractPkScriptAddrs(%x) %w", txout.PkScript, err)
		}
		if (class == txscript.WitnessV0ScriptHashTy || class == txscript.WitnessV1TaprootTy) && len(addresses) == 1 && addresses[0].EncodeAddress() == lockupAddress && requiredsigs == 1 {
			out = wire.NewOutPoint(tx.Hash(), uint32(i))
			if int64(amt) != txout.Value {
				return "", fmt.Errorf("bad amount: %v != %v", int64(amt), txout.Value)
			}
		}
	}
	if out == nil {
		return "", fmt.Errorf("lockupAddress: %v not found in the transaction: %v", lockupAddress, transactionHex)
	}
	return tx.Hash().String(), nil
}

type transactionStatus struct {
	Status      string `json:"status"`
	Transaction struct {
		ID  string `json:"id"`
		Hex string `json:"hex"`
		ETA int    `json:"eta",omitempty`
	} `json:"transaction",omitempty`
}

// GetTransaction return the transaction after paying the ln invoice
func GetTransaction(id, lockupAddress string, amt int64) (status, txid, tx string, eta int, err error) {
	buffer := new(bytes.Buffer)
	err = json.NewEncoder(buffer).Encode(struct {
		ID string `json:"id"`
	}{ID: id})
	if err != nil {
		err = fmt.Errorf("json encode %v: %w", id, err)
		return
	}
	resp, err := http.Post(apiURL+swapStatusEndpoint, "application/json", buffer)
	if err != nil {
		err = fmt.Errorf("swapstatus post %v: %w", apiURL+swapStatusEndpoint, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		e := struct {
			Error string `json:"error"`
		}{}
		err = json.NewDecoder(resp.Body).Decode(&e)
		if err != nil {
			err = fmt.Errorf("json decode (status: %v): %w", resp.Status, err)
			return
		}
		badRequestError := BadRequestError(e.Error)
		err = fmt.Errorf("createswap result (status: %v) %w", resp.Status, &badRequestError)
		return
	}

	var ts transactionStatus
	err = json.NewDecoder(resp.Body).Decode(&ts)
	if err != nil {
		err = fmt.Errorf("json decode (status ok): %w", err)
		return
	}
	if ts.Status != "transaction.mempool" && ts.Status != "transaction.confirmed" {
		err = ErrSwapNotFound
		return
	}

	if lockupAddress != "" {
		var calculatedTxid string
		calculatedTxid, err = CheckTransaction(ts.Transaction.Hex, lockupAddress, amt)
		if err != nil {
			err = fmt.Errorf("CheckTransaction(%v, %v, %v): %w)", ts.Transaction.Hex, lockupAddress, amt, err)
			return
		}
		if calculatedTxid != ts.Transaction.ID {
			err = fmt.Errorf("bad txid: %v != %v", ts.Transaction.ID, calculatedTxid)
			return
		}
	}
	status = ts.Status
	tx = ts.Transaction.Hex
	txid = ts.Transaction.ID
	eta = ts.Transaction.ETA
	return
}

// ClaimFees return the fees needed for the claimed transaction for a feePerKw
func ClaimFee(claimAddress string, feePerKw int64) (int64, error) {
	addr, err := btcutil.DecodeAddress(claimAddress, chain)
	if err != nil {
		return 0, fmt.Errorf("btcutil.DecodeAddress(%v) %w", addr, err)
	}
	claimScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return 0, fmt.Errorf("txscript.PayToAddrScript(%v): %w", addr.String(), err)
	}
	claimTx := wire.NewMsgTx(1)
	txIn := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
	txIn.Sequence = 0
	claimTx.AddTxIn(txIn)
	txOut := wire.TxOut{PkScript: claimScript}
	claimTx.AddTxOut(&txOut)

	// Calcluate the weight and the fee
	weight := 4*claimTx.SerializeSizeStripped() + claimWitnessInputSize*len(claimTx.TxIn)
	fee := chainfee.SatPerKWeight(feePerKw).FeeForWeight(int64(weight))
	return int64(fee), nil
}

type prevoutFetcher struct {
	txout *wire.TxOut
}

func newPrevoutFetcher(txout *wire.TxOut) *prevoutFetcher {
	return &prevoutFetcher{
		txout: txout,
	}
}

func (p *prevoutFetcher) FetchPrevOutput(wire.OutPoint) *wire.TxOut {
	return p.txout
}

func claimTransaction(
	script []byte,
	amt btcutil.Amount,
	outpoint *wire.OutPoint,
	claimAddress btcutil.Address,
	preimage []byte,
	privateKey []byte,
	fees btcutil.Amount,
	prevout *wire.TxOut,
) ([]byte, error) {
	claimTx := wire.NewMsgTx(1)
	txIn := wire.NewTxIn(outpoint, nil, nil)
	txIn.Sequence = 0
	claimTx.AddTxIn(txIn)

	claimScript, err := txscript.PayToAddrScript(claimAddress)
	if err != nil {
		return nil, fmt.Errorf("txscript.PayToAddrScript(%v): %w", claimAddress.String(), err)
	}
	txOut := wire.TxOut{PkScript: claimScript}
	claimTx.AddTxOut(&txOut)

	// Adjust the amount in the txout
	claimTx.TxOut[0].Value = int64(amt - fees)

	prevoutFetcher := newPrevoutFetcher(prevout)
	sigHashes := txscript.NewTxSigHashes(claimTx, prevoutFetcher)
	key, _ := btcec.PrivKeyFromBytes(privateKey)
	scriptSig, err := txscript.RawTxInWitnessSignature(claimTx, sigHashes, 0, int64(amt), script, txscript.SigHashAll, key)
	if err != nil {
		return nil, fmt.Errorf("txscript.RawTxInWitnessSignature: %w", err)
	}
	claimTx.TxIn[0].Witness = [][]byte{scriptSig, preimage, script}

	var rawTx bytes.Buffer
	err = claimTx.Serialize(&rawTx)
	if err != nil {
		return nil, fmt.Errorf("claimTx.Serialize %#v: %w", claimTx, err)
	}
	return rawTx.Bytes(), nil
}

func broadcastTransaction(tx string) (string, error) {
	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(struct {
		Currency       string `json:"currency"`
		TransactionHex string `json:"transactionHex"`
	}{"BTC", tx})
	if err != nil {
		return "", fmt.Errorf("json encode %v: %w", tx, err)
	}
	resp, err := http.Post(apiURL+broadcastTransactionEndpoint, "application/json", buffer)
	if err != nil {
		return "", fmt.Errorf("broadcasttransaction post %v: %w", apiURL+broadcastTransactionEndpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("broadcasttransaction result (status: %v)", resp.Status)
	}

	var tid struct {
		TransactionID string `json:"transactionId"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tid)
	if err != nil {
		return "", fmt.Errorf("json decode (status ok): %w", err)
	}
	return tid.TransactionID, nil
}

// ClaimTransaction returns the claim transaction to broadcast after sending it
// also to boltz
func ClaimTransaction(
	redeemScript, transactionHex string,
	claimAddress string,
	preimage, key string,
	fees int64,
) (string, error) {
	txSerialized, err := hex.DecodeString(transactionHex)
	if err != nil {
		return "", fmt.Errorf("hex.DecodeString(%v): %w", transactionHex, err)
	}
	tx, err := btcutil.NewTxFromBytes(txSerialized)
	if err != nil {
		return "", fmt.Errorf("btcutil.NewTxFromBytes(%x): %w", txSerialized, err)
	}

	script, err := hex.DecodeString(redeemScript)
	if err != nil {
		return "", fmt.Errorf("hex.DecodeString(%v): %w", redeemScript, err)
	}
	lockupAddress, err := addressWitnessScriptHash(script, chain)
	if err != nil {
		return "", fmt.Errorf("addressWitnessScriptHash %v: %w", script, err)
	}
	var out *wire.OutPoint
	var amt btcutil.Amount
	var outtx *wire.TxOut
	for i, txout := range tx.MsgTx().TxOut {
		class, addresses, requiredsigs, err := txscript.ExtractPkScriptAddrs(txout.PkScript, chain)
		if err != nil {
			return "", fmt.Errorf("txscript.ExtractPkScriptAddrs(%x) %w", txout.PkScript, err)
		}
		if (class == txscript.WitnessV0ScriptHashTy || class == txscript.WitnessV1TaprootTy) && requiredsigs == 1 &&
			len(addresses) == 1 && addresses[0].EncodeAddress() == lockupAddress.EncodeAddress() {
			out = wire.NewOutPoint(tx.Hash(), uint32(i))
			amt = btcutil.Amount(txout.Value)
			outtx = txout
		}
	}

	addr, err := btcutil.DecodeAddress(claimAddress, chain)
	if err != nil {
		return "", fmt.Errorf("btcutil.DecodeAddress(%v) %w", claimAddress, err)
	}

	preim, err := hex.DecodeString(preimage)
	if err != nil {
		return "", fmt.Errorf("hex.DecodeString(%v): %w", preimage, err)
	}
	privateKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("hex.DecodeString(%v): %w", key, err)
	}

	ctx, err := claimTransaction(script, amt, out, addr, preim, privateKey, btcutil.Amount(fees), outtx)
	if err != nil {
		return "", fmt.Errorf("claimTransaction: %w", err)
	}
	ctxHex := hex.EncodeToString(ctx)
	//Ignore the result of broadcasting the transaction via boltz
	_, _ = broadcastTransaction(ctxHex)
	return ctxHex, nil
}

func GetNodePubkey() (string, error) {
	resp, err := http.Get(apiURL + getNodesEndpoint)
	if err != nil {
		return "", fmt.Errorf("getpairs get %v: %w", apiURL+getPairsEndpoint, err)
	}
	defer resp.Body.Close()

	var nodes struct {
		Nodes map[string]struct {
			URIS    []string `json:"uris"`
			NodeKey string   `json:"nodeKey"`
		} `json:"nodes"`
	}

	err = json.NewDecoder(resp.Body).Decode(&nodes)
	if err != nil {
		return "", fmt.Errorf("json decode (status: %v): %w", resp.Status, err)
	}
	if b, ok := nodes.Nodes["BTC"]; ok {
		return b.NodeKey, nil
	}
	return "", fmt.Errorf("Pubkey not found")
}
