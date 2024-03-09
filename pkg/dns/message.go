package dns

import (
	"encoding/binary"
	"errors"
)

type MessageParser interface {
	Parse(data []byte) (*DNSMessage, error)
}

type DNSMessageParser struct{}

func NewDNSMessageParser() MessageParser {
	return &DNSMessageParser{}
}

func (h *DNSHeader) UnmarshalBinary(data []byte) error {
	h.ID = binary.BigEndian.Uint16(data[0:2])
	h.Query = data[2]&0x80 == 0
	h.Opcode = data[2] >> 3 & 0x0F
	h.AuthoritativeAnswer = data[2]&0x04 != 0
	h.Truncated = data[2]&0x02 != 0
	h.RecursionDesired = data[2]&0x01 != 0
	h.RecursionAvailable = data[3]&0x80 != 0
	h.Z = data[3] >> 4 & 0x07
	h.RCode = data[3] & 0x0F
	h.QuestionsCount = binary.BigEndian.Uint16(data[4:6])
	h.AnswersCount = binary.BigEndian.Uint16(data[6:8])
	h.AuthoritiesCount = binary.BigEndian.Uint16(data[8:10])
	h.AdditionalRRsCount = binary.BigEndian.Uint16(data[10:12])

	return nil
}

func (q *DNSQuestion) UnmarshalBinary(data []byte, offset int) (int, error) {
	q.Name, offset = parseDNSName(data, offset)

	if len(data) < offset+4 {
		return 0, errors.New("invalid DNS packet")
	}
	q.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	q.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4

	return offset, nil
}

func (p *DNSMessageParser) Parse(packet []byte) (*DNSMessage, error) {
	if len(packet) < 12 {
		return nil, errors.New("invalid DNS packet")
	}
	offset := 12
	var message DNSMessage
	var question DNSQuestion

	message.Header.UnmarshalBinary(packet[:offset])

	for i := 0; i < int(message.Header.QuestionsCount); i++ {
		var err error
		offset, err = question.UnmarshalBinary(packet, offset)
		if err == nil {
			message.Questions = append(message.Questions, question)
		}
	}

	return &message, nil
}

func parseDNSName(packet []byte, offset int) (string, int) {
	var name []byte
	for {
		length := int(packet[offset])
		if length == 0 {
			offset++
			break
		}
		offset++
		name = append(name, packet[offset:offset+length]...)
		name = append(name, '.')
		offset += length
	}
	return string(name), offset
}
