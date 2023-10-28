package zctcpip

var zeroChecksum = [2]byte{0x00, 0x00}

func Sum(b []byte) uint32 {
	// TODO use neon on arm and AVX on amd64
	var sum uint32
	n := len(b)
	if n&1 != 0 {
		n--
		sum += uint32(b[n]) << 8
	}

	for i := 0; i < n; i += 2 {
		sum += (uint32(b[i]) << 8) | uint32(b[i+1])
	}
	return sum
}

// Checksum for Internet Protocol family headers
func Checksum(sum uint32, b []byte) (answer [2]byte) {
	sum += Sum(b)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	sum = ^sum
	answer[0] = byte(sum >> 8)
	answer[1] = byte(sum)
	return
}

func SetIPv4(packet []byte) {
	packet[0] = (packet[0] & 0x0f) | (4 << 4)
}
