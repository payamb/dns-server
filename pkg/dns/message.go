package dns

import (
	"encoding/binary"
	"errors"
)

func ParseMessage(packet []byte) (*DNSMessage, error) {
	if len(packet) < 12 {
		return nil, errors.New("invalid DNS packet")
	}

	var message DNSMessage

	// Parse DNS header
	message.Header.ID = binary.BigEndian.Uint16(packet[0:2])
	message.Header.Query = (packet[2] & 0x80) != 1
	message.Header.Opcode = uint8(packet[2] >> 3 & 0x0F)
	message.Header.AuthoritativeAnswer = (packet[2] & 0x04) != 0
	message.Header.Truncated = (packet[2] & 0x02) != 0
	message.Header.RecursionDesired = (packet[2] & 0x01) != 0
	message.Header.RecursionAvailable = (packet[3] & 0x80) != 0
	message.Header.Z = uint8(packet[3] >> 4 & 0x07)
	message.Header.RCode = uint8(packet[3] & 0x0F)
	message.Header.QuestionsCount = binary.BigEndian.Uint16(packet[4:6])
	message.Header.AnswersCount = binary.BigEndian.Uint16(packet[6:8])
	message.Header.AuthoritiesCount = binary.BigEndian.Uint16(packet[8:10])
	message.Header.AdditionalRRsCount = binary.BigEndian.Uint16(packet[10:12])
	offset := 12

	// Parse DNS questions
	for i := 0; i < int(message.Header.QuestionsCount); i++ {
		var question DNSQuestion
		question.Name, offset = parseDNSName(packet, offset)
		if len(packet) < offset+4 {
			return nil, errors.New("invalid DNS packet")
		}
		question.Type = binary.BigEndian.Uint16(packet[offset : offset+2])
		question.Class = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4
		message.Questions = append(message.Questions, question)
	}

	// Parse DNS answers, authority, and additional records
	// message.Answers = parseRRs(packet, &offset, int(message.Header.ANCOUNT))
	// message.Authority = parseRRs(packet, &offset, int(message.Header.NSCOUNT))
	// message.Additional = parseRRs(packet, &offset, int(message.Header.ARCOUNT))

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
