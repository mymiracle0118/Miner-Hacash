package minerpool

import (
	"bytes"
	"fmt"
	"github.com/hacash/core/fields"
)

const (
	MinerPoolStatusSize = 4 * 12
)

type MinerPoolStatus struct {
	FindBlockHashHeightTableLastestNumber fields.VarUint4 // Latest value of excavated block ID table
	TransferHashTableLastestNumber        fields.VarUint4 // Latest value of transfer serial number table
}

func NewEmptyMinerPoolStatus() *MinerPoolStatus {
	return &MinerPoolStatus{
		0, 0,
	}
}

func (s *MinerPoolStatus) Serialize() ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	b1, _ := s.FindBlockHashHeightTableLastestNumber.Serialize()
	b2, _ := s.TransferHashTableLastestNumber.Serialize()
	buf.Write(b1)
	buf.Write(b2)
	resbuf := make([]byte, MinerPoolStatusSize)
	copy(resbuf, buf.Bytes())
	return resbuf, nil
}

func (s *MinerPoolStatus) Parse(buf []byte, seek uint32) (uint32, error) {
	if uint32(len(buf))-seek < 4+4 {
		return 0, fmt.Errorf("size error.")
	}
	seek, _ = s.FindBlockHashHeightTableLastestNumber.Parse(buf, seek)
	seek, _ = s.TransferHashTableLastestNumber.Parse(buf, seek)
	return seek, nil
}

func (s *MinerPoolStatus) Size() uint32 {
	return MinerPoolStatusSize
}
