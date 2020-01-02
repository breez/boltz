package boltz

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	createSwapEndpoint           = "/createswap"
	swapStatusEndpoint           = "/swapstatus"
	broadcastTransactionEndpoint = "/broadcasttransaction"
	claimWitnessInputSize        = 1 + 1 + 73 + 1 + 32 + 1 + 100
)

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

func createReverseSwap(amt int64, preimage []byte, key *btcec.PrivateKey) (*boltzReverseSwap, error) {
	h := sha256.Sum256(preimage)
	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(struct {
		Type           string `json:"type"`
		PairID         string `json:"pairId"`
		OrderSide      string `json:"orderSide"`
		InvoiceAmount  int64  `json:"invoiceAmount"`
		PreimageHash   string `json:"preimageHash"`
		ClaimPublicKey string `json:"claimPublicKey"`
	}{
		Type:           "reversesubmarine",
		PairID:         "BTC/BTC",
		OrderSide:      "buy",
		InvoiceAmount:  amt,
		PreimageHash:   hex.EncodeToString(h[:]),
		ClaimPublicKey: hex.EncodeToString(key.PubKey().SerializeCompressed()),
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
		return nil, fmt.Errorf("createswap result (status: %v) %v", resp.Status, e.Error)
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

func checkReverseSwap(preimage []byte, key *btcec.PrivateKey, rs *boltzReverseSwap) error {
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
	k, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("btcec.NewPrivateKey: %w", err)
	}
	return k, nil
}

// NewReverseSwap begins the reverse submarine process.
func NewReverseSwap(amt btcutil.Amount) (*ReverseSwap, error) {
	preimage := getPreimage()

	key, err := getPrivate()
	if err != nil {
		return nil, fmt.Errorf("getPrivate: %w", err)
	}

	rs, err := createReverseSwap(int64(amt), preimage, key)
	if err != nil {
		return nil, fmt.Errorf("createReverseSwap amt:%v, preimage:%x, key:%x; %w", amt, preimage, key, err)
	}

	err = checkReverseSwap(preimage, key, rs)
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
		if class == txscript.WitnessV0ScriptHashTy && len(addresses) == 1 && addresses[0].EncodeAddress() == lockupAddress && requiredsigs == 1 {
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
	Status         string `json:"status"`
	TransactionID  string `json:"transactionId"`
	TransactionHex string `json:"transactionHex"`
}

// GetTransaction return the transaction after paying the ln invoice
func GetTransaction(id, lockupAddress string, amt int64) (status, txid, tx string, err error) {
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
		err = fmt.Errorf("swapstatus result (status: %v) %v", resp.Status, e.Error)
		return
	}

	var ts transactionStatus
	err = json.NewDecoder(resp.Body).Decode(&ts)
	if err != nil {
		err = fmt.Errorf("json decode (status ok): %w", err)
		return
	}
	log.Printf("%#v\n", ts)
	if ts.Status != "transaction.mempool" && ts.Status != "transaction.confirmed" {
		err = fmt.Errorf("transaction not in mempool or settled/canceled")
		return
	}

	var calculatedTxid string
	calculatedTxid, err = CheckTransaction(ts.TransactionHex, lockupAddress, amt)
	if err != nil {
		err = fmt.Errorf("CheckTransaction(%v, %v, %v): %w)", ts.TransactionHex, lockupAddress, amt, err)
		return
	}
	if calculatedTxid != ts.TransactionID {
		err = fmt.Errorf("bad txid: %v != %v", ts.TransactionID, calculatedTxid)
		return
	}

	tx = ts.TransactionHex
	txid = ts.TransactionID
	return
}

func claimTransaction(
	script []byte,
	amt btcutil.Amount,
	txout *wire.OutPoint,
	claimAddress btcutil.Address,
	preimage []byte,
	privateKey []byte,
	feePerKw chainfee.SatPerKWeight,
) ([]byte, error) {
	claimTx := wire.NewMsgTx(1)
	txIn := wire.NewTxIn(txout, nil, nil)
	txIn.Sequence = 0
	claimTx.AddTxIn(txIn)

	claimScript, err := txscript.PayToAddrScript(claimAddress)
	if err != nil {
		return nil, fmt.Errorf("txscript.PayToAddrScript(%v): %w", claimAddress.String(), err)
	}
	txOut := wire.TxOut{PkScript: claimScript}
	claimTx.AddTxOut(&txOut)

	// Calcluate the weight and the fee
	weight := 4*claimTx.SerializeSizeStripped() + claimWitnessInputSize*len(claimTx.TxIn)
	// Adjust the amount in the txout
	claimTx.TxOut[0].Value = int64(amt - feePerKw.FeeForWeight(int64(weight)))

	sigHashes := txscript.NewTxSigHashes(claimTx)
	key, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKey)
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
	feePerKw int64,
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
	for i, txout := range tx.MsgTx().TxOut {
		class, addresses, requiredsigs, err := txscript.ExtractPkScriptAddrs(txout.PkScript, chain)
		if err != nil {
			return "", fmt.Errorf("txscript.ExtractPkScriptAddrs(%x) %w", txout.PkScript, err)
		}
		if class == txscript.WitnessV0ScriptHashTy && requiredsigs == 1 &&
			len(addresses) == 1 && addresses[0].EncodeAddress() == lockupAddress.EncodeAddress() {
			out = wire.NewOutPoint(tx.Hash(), uint32(i))
			amt = btcutil.Amount(txout.Value)
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

	ctx, err := claimTransaction(script, amt, out, addr, preim, privateKey, chainfee.SatPerKWeight(feePerKw))
	if err != nil {
		return "", fmt.Errorf("claimTransaction: %w", err)
	}
	ctxHex := hex.EncodeToString(ctx)
	//Ignore the result of broadcasting the transaction via boltz
	_, _ = broadcastTransaction(ctxHex)
	return ctxHex, nil
}
