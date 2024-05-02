package memtxpool

import (
	"fmt"
	"github.com/hacash/core/actions"
	"github.com/hacash/core/interfaces"
	"time"
)

func (p *MemTxPool) AddTx(tx interfaces.Transaction) error {
	p.changeLock.Lock()
	defer p.changeLock.Unlock()

	txitem := &TxItem{
		tx:        tx,
		hash:      tx.Hash(),
		size:      tx.Size(),
		feepurity: tx.FeePurity(),
		diamond:   nil,
	}

	if p.blockchain == nil {
		return fmt.Errorf("[MemTxPool] blockchain is not be set.")
	}

	// check tx time
	if tx.GetTimestamp() > uint64(time.Now().Unix()) {
		return fmt.Errorf("tx timestamp cannot more than now.")
	}

	// check pool max
	if p.maxcount > 0 && p.txTotalCount+1 > p.maxcount {
		return fmt.Errorf("Tx pool max count %d and too mach.", p.maxcount)
	}
	if p.maxsize > 0 && p.txTotalSize+uint64(txitem.size) > p.maxsize {
		return fmt.Errorf("Tx pool max size %d and overflow size.", p.maxsize)
	}

	// Whether it is a diamond mining transaction
	var isDiamondCreateTx *actions.Action_4_DiamondCreate = nil
	// Is it new and added for the first time
	isTxFirstAdd := true

	// do add is diamond ?
	for _, act := range tx.GetActionList() {
		if dcact, ok := act.(*actions.Action_4_DiamondCreate); ok {
			isDiamondCreateTx = dcact
		}
	}

	// check exist
	if isDiamondCreateTx != nil {
		// Diamond Trading
		if havitem := p.diamondCreateTxGroup.Find(txitem.hash); havitem != nil {
			//fmt.Println(havitem.feepurity, txitem.feepurity)
			if txitem.feepurity <= havitem.feepurity {
				return fmt.Errorf("already exist tx %s and fee purity more than or equal the new one.", txitem.hash.ToHex())
			}
			// check fee
			txfee := txitem.tx.GetFee()
			febls, e := p.blockchain.GetChainEngineKernel().StateRead().Balance(txitem.tx.GetAddress())
			if e != nil {
				return e
			}
			blastr := "ㄜ0:0"
			if febls != nil {
				blastr = febls.Hacash.ToFinString()
			}
			if febls == nil || febls.Hacash.LessThan(txfee) {
				// The balance is insufficient to pay the service charge
				return fmt.Errorf("fee address balance %s need not less than %s but got %s.", txitem.tx.GetAddress(), txfee.ToFinString(), blastr)
			}
			// check ok
			p.diamondCreateTxGroup.RemoveItem(havitem)
			isTxFirstAdd = false
		}
	} else {
		// Ordinary transaction
		if havitem := p.simpleTxGroup.Find(txitem.hash); havitem != nil {
			//fmt.Println(havitem.feepurity, txitem.feepurity)
			if txitem.feepurity <= havitem.feepurity {
				return fmt.Errorf("already exist tx %s and fee purity more than or equal the new one.", txitem.hash.ToHex())
			}
			if p.simpleTxGroup.RemoveItem(havitem) {
				// sub count
				p.txTotalCount -= 1
				p.txTotalSize -= uint64(havitem.size)
			}
			isTxFirstAdd = false
		}

	}
	// do add is diamond ?
	if isDiamondCreateTx != nil {
		dcact := isDiamondCreateTx
		// is diamond create trs
		err := p.checkDiamondCreate(tx, dcact)
		if err != nil {
			return err
		}
		txitem.diamond = dcact // diamond mark
		p.diamondCreateTxGroup.Add(txitem)
		// feed send
		if p.isBanEventSubscribe == false {
			p.addTxSuccess.Send(tx)
		}
		if isTxFirstAdd {
			fmt.Println("memtxpool add diamond create tx:", tx.Hash().ToHex(), ", diamond:", dcact.Number, string(dcact.Diamond))
		}
		return nil // add successfully !
	}

	// General transaction inspection and statistics
	// check tx
	txerr := p.blockchain.ValidateTransactionForTxPool(tx.(interfaces.Transaction))
	//, func(tmpState interfacev2.ChainState) {
	//	// 标记是矿池中验证tx
	//	tmpState.SetInTxPool(true)
	//})
	if txerr != nil {
		return txerr
	}
	// do add simple
	p.simpleTxGroup.Add(txitem)
	// add count
	p.txTotalCount += 1
	p.txTotalSize += uint64(txitem.size)

	// feed send
	if p.isBanEventSubscribe == false {
		p.addTxSuccess.Send(tx)
	}

	if isTxFirstAdd {
		fmt.Println("memtxpool add tx:", tx.Hash().ToHex())
	}

	return nil // add successfully !
}
