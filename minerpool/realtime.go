package minerpool

import (
	"github.com/hacash/core/blocks"
	"github.com/hacash/core/fields"
	"github.com/hacash/core/interfaces"
	"github.com/hacash/miner/message"
	"github.com/hacash/mint/coinbase"
	"sync"
	"sync/atomic"
)

type RealtimePeriod struct {
	minerpool *MinerPool

	miningSuccessBlock interfaces.Block

	targetBlock interfaces.Block

	realtimeAccounts map[string]*Account // [*Account]

	autoIncrementCoinbaseMsgNum uint32

	outputBlockCh *chan interfaces.Block

	changeLock sync.Mutex
}

func NewRealtimePeriod(minerpool *MinerPool, block interfaces.Block) *RealtimePeriod {
	per := &RealtimePeriod{
		miningSuccessBlock:          nil,
		minerpool:                   minerpool,
		targetBlock:                 block,
		realtimeAccounts:            make(map[string]*Account),
		autoIncrementCoinbaseMsgNum: 0,
		outputBlockCh:               nil,
	}
	return per
}

func (r *RealtimePeriod) getAutoIncrementCoinbaseMsgNum() uint32 {

	atomic.AddUint32(&r.autoIncrementCoinbaseMsgNum, 1)
	return r.autoIncrementCoinbaseMsgNum
}

func (r *RealtimePeriod) sendMiningStuffMsgToAllClient() {
	for _, v := range r.realtimeAccounts {
		v.activeClients.Each(func(i interface{}) bool {
			cli := i.(*Client)
			r.sendMiningStuffMsg(cli)
			return false
		})
	}
}

func (r *RealtimePeriod) sendMiningStuffMsg(client *Client) {
	r.changeLock.Lock()
	defer r.changeLock.Unlock()

	if r.targetBlock == nil {
		return
	}
	cbmsgnum := r.getAutoIncrementCoinbaseMsgNum()
	msgobj := message.NewPowMasterMsg()
	msgobj.CoinbaseMsgNum = fields.VarUint4(cbmsgnum)
	//fmt.Println("sendMiningStuffMsg", uint32(msgobj.CoinbaseMsgNum) )
	coinbase.UpdateBlockCoinbaseMessageForMiner(r.targetBlock, uint32(msgobj.CoinbaseMsgNum))
	r.targetBlock.SetMrklRoot(blocks.CalculateMrklRoot(r.targetBlock.GetTrsList()))
	msgobj.BlockHeadMeta = r.targetBlock
	// create work item
	wkitem := NewWorkItem(client, r.targetBlock, cbmsgnum)
	client.addWorkItem(wkitem)
	// send data
	data, _ := msgobj.Serialize()
	go client.conn.Write(data)
}

// find ok
func (r *RealtimePeriod) successFindNewBlock(block interfaces.Block) {
	if r.outputBlockCh != nil {
		go func() {
			*r.outputBlockCh <- block // Dig out the block and pass it to miner
		}()
	}
}

func (r *RealtimePeriod) IsOverEndBlock(blkheibts []byte) bool {
	tarhei := fields.BlockHeight(0)
	tarhei.Parse(blkheibts[0:5], 0)
	return uint64(tarhei) != r.targetBlock.GetHeight()
}

// End current mining
func (r *RealtimePeriod) endCurrentMining() {
	//fmt.Println("+++++++++++++++++++++ endCurrentMining ")
	go func() {
		for _, acc := range r.realtimeAccounts {
			clients := acc.activeClients.ToSlice()
			for _, cli := range clients {
				client := cli.(*Client)
				//fmt.Println(" -client.conn.Write([]byte(end_current_mining) ")
				client.conn.Write([]byte("end_current_mining"))
				// Unable to end the connection, waiting to upload the calculation force statistics
			}
		}
	}()
}

///////////////////////////

func (r *RealtimePeriod) GetAccounts() []*Account {
	res := make([]*Account, 0)
	for _, acc := range r.realtimeAccounts {
		//fmt.Println("-----", acc.address.ToReadable())
		res = append(res, acc)
	}
	return res
}
