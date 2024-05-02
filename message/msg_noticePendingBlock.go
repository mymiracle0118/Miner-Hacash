package message

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/hacash/core/blocks"
	"github.com/hacash/core/fields"
	"github.com/hacash/core/interfaces"
	"github.com/hacash/core/transactions"
)

/**

下发通知挖矿的区块

*/

type MsgPendingMiningBlockStuff struct {
	BlockHeadMeta                          interfaces.Block                     // Block head and meta
	CoinbaseTx                             *transactions.Transaction_0_Coinbase // Coinbase transaction
	MrklRelatedTreeListForCoinbaseTxModify []fields.Hash                        // Merkel Tree Association hash
	// cache data
	mint_successed bool
}

// interfaces.PowWorkerMiningStuffItem

func (m *MsgPendingMiningBlockStuff) SetMiningSuccessed(ok bool) {
	m.mint_successed = ok
}
func (m MsgPendingMiningBlockStuff) GetMiningSuccessed() bool {
	return m.mint_successed
}
func (m MsgPendingMiningBlockStuff) GetHeadMetaBlock() interfaces.Block {
	return m.BlockHeadMeta
}
func (m MsgPendingMiningBlockStuff) GetCoinbaseNonce() []byte {
	return m.CoinbaseTx.MinerNonce
}
func (m MsgPendingMiningBlockStuff) GetHeadNonce() []byte {
	ncbts := make([]byte, 4)
	binary.BigEndian.PutUint32(ncbts, m.BlockHeadMeta.GetNonce())
	return ncbts
}
func (m MsgPendingMiningBlockStuff) SetHeadNonce(nonce []byte) {
	m.BlockHeadMeta.SetNonce(binary.BigEndian.Uint32(nonce))
}
func (m MsgPendingMiningBlockStuff) CopyForMiningByRandomSetCoinbaseNonce() interfaces.PowWorkerMiningStuffItem {
	newcbnonce := make([]byte, 32)
	rand.Read(newcbnonce)
	//fmt.Println(newcbnonce)
	newstuff, _ := m.CalculateBlockHashByBothNonce([]byte{0, 0, 0, 0}, newcbnonce, true) // copy
	//fmt.Println(newstuff.GetHeadMetaBlock().GetMrklRoot())
	return newstuff
}

// Creating mining stuff
func CreatePendingMiningBlockStuffByBlock(block interfaces.Block) (*MsgPendingMiningBlockStuff, error) {
	stuff := &MsgPendingMiningBlockStuff{
		BlockHeadMeta: block.CopyForMining(),
	}

	trxs := block.GetTrsList()
	if len(trxs) < 1 {
		return nil, fmt.Errorf("Block Transactions len error")
	}
	cbtrs := trxs[0]
	cbtx, ok := cbtrs.(*transactions.Transaction_0_Coinbase)
	if ok == false {
		return nil, fmt.Errorf("Block Transaction_0_Coinbase error")
	}
	stuff.CoinbaseTx = cbtx
	stuff.MrklRelatedTreeListForCoinbaseTxModify = blocks.PickMrklListForCoinbaseTxModify(trxs)
	return stuff, nil
}

// serialize
func (m MsgPendingMiningBlockStuff) Serialize() []byte {
	buf := bytes.NewBuffer([]byte{})
	b1, _ := m.BlockHeadMeta.SerializeExcludeTransactions()
	buf.Write(b1)
	b2, _ := m.CoinbaseTx.Serialize()
	buf.Write(b2)
	mrklsize := len(m.MrklRelatedTreeListForCoinbaseTxModify)
	mrklsizebytes := []byte{0, 0}
	binary.BigEndian.PutUint16(mrklsizebytes, uint16(mrklsize))
	buf.Write(mrklsizebytes)
	for i := 0; i < int(mrklsize); i++ {
		buf.Write(m.MrklRelatedTreeListForCoinbaseTxModify[i])
	}
	// all ok
	return buf.Bytes()
}

// Deserialization
func (m *MsgPendingMiningBlockStuff) Parse(buf []byte, seek uint32) (uint32, error) {
	var e error = nil
	trsptr, seek, e := blocks.ParseExcludeTransactions(buf, seek)
	m.BlockHeadMeta = trsptr.(interfaces.Block)
	if e != nil {
		return 0, e
	}
	var trs interfaces.Transaction = nil
	trs, seek, e = transactions.ParseTransaction(buf, seek)
	if e != nil {
		return 0, e
	}
	cbtx, ok := trs.(*transactions.Transaction_0_Coinbase)
	if ok == false {
		return 0, fmt.Errorf("tx must be Transaction_0_Coinbase")
	}
	m.CoinbaseTx = cbtx
	// mrkl
	if len(buf) < int(seek)+2 {
		return 0, fmt.Errorf("buf len error")
	}
	mrklsize := binary.BigEndian.Uint16(buf[seek : seek+2])
	hxlist := make([]fields.Hash, 0)
	seek += 2
	for i := 0; i < int(mrklsize); i++ {
		if len(buf) < int(seek)+32 {
			return 0, fmt.Errorf("buf len error")
		}
		hxlist = append(hxlist, buf[seek:seek+32])
		seek += 32
	}
	m.MrklRelatedTreeListForCoinbaseTxModify = hxlist
	// all ok
	return seek, nil
}

// Calculate block hash by setting nonce value
func (m MsgPendingMiningBlockStuff) CalculateBlockHashByBothNonce(headNonce fields.Bytes4, coinbaseNonce fields.Bytes32, retcopy bool) (*MsgPendingMiningBlockStuff, fields.Hash) {
	//
	newblock := m.BlockHeadMeta.CopyForMining()
	newblock.SetNonce(binary.BigEndian.Uint32(headNonce))
	/// copy coinbase hash
	cbnonce := make([]byte, 32)
	copy(cbnonce, coinbaseNonce)
	coinbasetxcopy := m.CoinbaseTx.Copy()
	newcbtx := coinbasetxcopy.(*transactions.Transaction_0_Coinbase)
	if newcbtx == nil {
		panic("m.CoinbaseTx must be a *transactions.Transaction_0_Coinbase")
	}
	newcbtx.MinerNonce = cbnonce
	// Calculate mrkl root
	cbtxhx := newcbtx.Hash()
	mrklroot := blocks.CalculateMrklRootByCoinbaseTxModify(cbtxhx, m.MrklRelatedTreeListForCoinbaseTxModify)
	newblock.SetMrklRoot(mrklroot)
	// hash
	blkhx := newblock.HashFresh()
	// copy
	var copystuff *MsgPendingMiningBlockStuff = nil
	if retcopy {
		copystuff = &MsgPendingMiningBlockStuff{
			BlockHeadMeta:                          newblock,
			CoinbaseTx:                             newcbtx,
			MrklRelatedTreeListForCoinbaseTxModify: m.MrklRelatedTreeListForCoinbaseTxModify,
		}
		realtxs := newblock.GetTrsList()
		if len(realtxs) > 0 {
			realtxs[0] = newcbtx // copy coinbase tx
		}
	}
	return copystuff, blkhx
}

// Calculate block hash by setting nonce value
func (m MsgPendingMiningBlockStuff) CalculateBlockHashByMiningResult(result *MsgReportMiningResult, retcopy bool) (*MsgPendingMiningBlockStuff, fields.Hash) {
	return m.CalculateBlockHashByBothNonce(result.HeadNonce, result.CoinbaseNonce, retcopy)
}
