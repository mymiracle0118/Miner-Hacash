package message

import (
	"bytes"
	"github.com/hacash/core/fields"
)

/**

服务器响应

*/

const MsgWorkerServerResponseSize = 2 + 1

type MsgServerResponse struct {
	RetCode                  fields.VarUint2 // Response code: 0. 正确可连接 1.版本不匹配   2. 连接数过多   等等
	AcceptHashrateStatistics fields.Bool     // Whether to accept calculation force statistics
}

// serialize
func (m MsgServerResponse) Serialize() []byte {

	buf := bytes.NewBuffer([]byte{})
	b1, _ := m.RetCode.Serialize()
	b2, _ := m.AcceptHashrateStatistics.Serialize()
	buf.Write(b1)
	buf.Write(b2)

	return buf.Bytes()
}

// Deserialization
func (m *MsgServerResponse) Parse(buf []byte, seek uint32) (uint32, error) {
	var e error = nil
	seek, e = m.RetCode.Parse(buf, seek)
	if e != nil {
		return 0, e
	}
	seek, e = m.AcceptHashrateStatistics.Parse(buf, seek)
	if e != nil {
		return 0, e
	}
	return seek, nil
}
