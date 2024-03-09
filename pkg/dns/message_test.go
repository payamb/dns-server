package dns

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestParseMessage(t *testing.T) {
	// Test case 1: Valid DNS packet
	// packet := []byte{
	// 	0x12, 0x34, // ID
	// 	0x01, 0x00, // Flags
	// 	0x00, 0x01, // Questions count
	// 	0x00, 0x00, // Answers count
	// 	0x00, 0x00, // Authorities count
	// 	0x00, 0x00, // Additional RRs count
	// }
	packet, err := hex.DecodeString("1432010000010000000000000662616261656502636f02756b00000f0001")
	if err != nil {
		fmt.Println("Cannot parse the hex input")
	}
	message, err := ParseMessage(packet)
	// &{Header:{ID:5170 Query:true Opcode:0 AuthoritativeAnswer:false Truncated:false RecursionDesired:true RecursionAvailable:false Z:0 RCode:0 QuestionsCount:1 AnswersCount:0 AuthoritiesCount:0 AdditionalRRsCount:0} Questions:[{Name:babaee.co.uk. Type:15 Class:1}] Answers:[] Authority:[] Additional:[]}
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if message.Header.ID != 5170 {
		t.Errorf("Expected ID 5170, got %x", message.Header.ID)
	}
	if message.Header.Query != true {
		t.Error("Expected Query to be true")
	}
	if message.Header.Opcode != 0 {
		t.Errorf("Expected Opcode 0, got %d", message.Header.Opcode)
	}
	if message.Header.AuthoritativeAnswer {
		t.Error("Expected AuthoritativeAnswer to be false")
	}
	if message.Header.Truncated {
		t.Error("Expected Truncated to be false")
	}
	if !message.Header.RecursionDesired {
		t.Error("Expected RecursionDesired to be true")
	}
	if message.Header.RecursionAvailable {
		t.Error("Expected RecursionAvailable to be false")
	}
	if message.Header.Z != 0 {
		t.Errorf("Expected Z 0, got %d", message.Header.Z)
	}
	if message.Header.RCode != 0 {
		t.Errorf("Expected RCode 0, got %d", message.Header.RCode)
	}
	if message.Header.QuestionsCount != 1 {
		t.Errorf("Expected QuestionsCount 1, got %d", message.Header.QuestionsCount)
	}
	if message.Header.AnswersCount != 0 {
		t.Errorf("Expected AnswersCount 0, got %d", message.Header.AnswersCount)
	}
	if message.Header.AuthoritiesCount != 0 {
		t.Errorf("Expected AuthoritiesCount 0, got %d", message.Header.AuthoritiesCount)
	}
	if message.Header.AdditionalRRsCount != 0 {
		t.Errorf("Expected AdditionalRRsCount 0, got %d", message.Header.AdditionalRRsCount)
	}

	// Test case 2: Invalid DNS packet (too short)
	// packet = []byte{0x12, 0x34}
	// message, err = ParseMessage(packet)
	// if err == nil {
	// 	t.Error("Expected an error for invalid packet")
	// }
	// if message != nil {
	// 	t.Error("Expected message to be nil for invalid packet")
	// }
}
