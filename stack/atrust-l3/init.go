package atrustl3

const MTU uint32 = 1400

const (
	l3Version        = 0x05
	cmdAuthReq       = 0x13
	cmdAuthResp      = 0x93
	cmdDataReq       = 0x14
	cmdDataResp      = 0x94
	cmdHeartbeatReq  = 0x15
	cmdHeartbeatResp = 0x95
	cmdSecondVipReq  = 0x16
	cmdSecondVipResp = 0x96
)
