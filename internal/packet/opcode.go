package packet

import (
	"fmt"
)

// OpenVPN Opcodes
const (
	OpControlHardResetClientV1 = 1
	OpControlHardResetServerV1 = 2
	OpControlSoftResetV1       = 3
	OpControlV1                = 4
	OpAckV1                    = 5
	OpDataV1                   = 6
	OpControlHardResetClientV2 = 7
	OpControlHardResetServerV2 = 8
	OpDataV2                   = 9
)

// OpenVPN Constants
const (
	SessionIDSize = 8
	PacketIDSize  = 4
)

// OpcodeToString converts opcode to string
func OpcodeToString(op byte) string {
	switch op {
	case OpControlHardResetClientV1:
		return "CONTROL_HARD_RESET_CLIENT_V1"
	case OpControlHardResetServerV1:
		return "CONTROL_HARD_RESET_SERVER_V1"
	case OpControlSoftResetV1:
		return "CONTROL_SOFT_RESET_V1"
	case OpControlV1:
		return "CONTROL_V1"
	case OpAckV1:
		return "ACK_V1"
	case OpDataV1:
		return "DATA_V1"
	case OpControlHardResetClientV2:
		return "CONTROL_HARD_RESET_CLIENT_V2"
	case OpControlHardResetServerV2:
		return "CONTROL_HARD_RESET_SERVER_V2"
	case OpDataV2:
		return "DATA_V2"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", op)
	}
}
