package dns

const (
	OpcodeQuery        = 0
	OpcodeInverseQuery = 1
	OpcodeStatus       = 2
	OpcodeNotify       = 4
	OpcodeUpdate       = 5
)

const (
	TypeA      uint16 = 1
	TypeNS     uint16 = 2
	TypeMD     uint16 = 3
	TypeMF     uint16 = 4
	TypeCNAME  uint16 = 5
	TypeSOA    uint16 = 6
	TypeMB     uint16 = 7
	TypeMG     uint16 = 8
	TypeMR     uint16 = 9
	TypeNULL   uint16 = 10
	TypeWKS    uint16 = 11
	TypePTR    uint16 = 12
	TypeHINFO  uint16 = 13
	TypeMINFO  uint16 = 14
	TypeMX     uint16 = 15
	TypeTXT    uint16 = 16
	TypeAAAA   uint16 = 28
	TypeSRV    uint16 = 33
	TypeOPT    uint16 = 41
	TypeDS     uint16 = 43
	TypeRRSIG  uint16 = 46
	TypeNSEC   uint16 = 47
	TypeDNSKEY uint16 = 48
	TypeTLSA   uint16 = 52
	TypeSMIMEA uint16 = 53
	TypeANY    uint16 = 255
)

type DNSHeader struct {
	ID                  uint16
	Query               bool
	Opcode              uint8
	AuthoritativeAnswer bool
	Truncated           bool
	RecursionDesired    bool
	RecursionAvailable  bool
	Z                   uint8
	RCode               uint8
	QuestionsCount      uint16
	AnswersCount        uint16
	AuthoritiesCount    uint16
	AdditionalRRsCount  uint16
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSResourceRecord struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   []byte
}

type DNSMessage struct {
	Header     DNSHeader
	Questions  []DNSQuestion
	Answers    []DNSResourceRecord
	Authority  []DNSResourceRecord
	Additional []DNSResourceRecord
}
