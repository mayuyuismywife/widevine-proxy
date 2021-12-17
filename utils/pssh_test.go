package widevineutils

import (
	"encoding/base64"
	"testing"
)

func TestPaddingNumber(t *testing.T) {
	s := "5"
	if paddingNumber(s) != "05" {
		t.Error()
	}

	s = "005"
	if paddingNumber(s) != "05" {
		t.Error()
	}
}

func TestParse(t *testing.T) {
	testDataBin := "AAAAOHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABgSEJPkt/Dij+qHMEpog1vObHFI49yVmwY="
	psshBox, _ := base64.StdEncoding.DecodeString(testDataBin)
	pssh := NewPSSH(psshBox)
	pssh.Parse()
	if pssh.Summary == nil {
		t.Error("pssh summary must not be nil")
	}
	if pssh.Summary.SizeHex != "00000038" {
		t.Errorf("Summary.SizeHex must be 00000038 got %s", pssh.Summary.SizeHex)
	}
	if pssh.Summary.SizeDecimal != 56 {
		t.Errorf("Summary.SizeHex must be 198 got %d", pssh.Summary.SizeDecimal)
	}
	if pssh.Summary.Type != "70737368" {
		t.Errorf("Summary.Type must be 70737368 got %s", pssh.Summary.Type)
	}
	if pssh.Summary.Version != "00" {
		t.Errorf("Summary.Version must be 00 got %s", pssh.Summary.Version)
	}
	if pssh.Summary.Flag != "000000" {
		t.Errorf("Summary.Flag must be 000000 got %s", pssh.Summary.Flag)
	}
	if pssh.Summary.DRMSystemID != "edef8ba979d64acea3c827dcd51d21ed" {
		t.Errorf("Summary.DRMSystemID must be edef8ba979d64acea3c827dcd51d21ed got %s", pssh.Summary.DRMSystemID)
	}
	if pssh.Summary.DataSize != 24 {
		t.Errorf("Summary.Data must be 24 got %d", pssh.Summary.DataSize)
	}

	dataExpected := "121093e4b7f0e28fea87304a68835bce6c7148e3dc959b06"
	if pssh.Summary.DataHex != dataExpected {
		t.Errorf("Summary.Data must be %s got %s", dataExpected, pssh.Summary.DataHex)
	}

	if len(pssh.Summary.KeyIDs) != 1 {
		t.Errorf("Summary.KeyIDs must be 1 got %d", len(pssh.Summary.KeyIDs))
	}

	if pssh.Summary.KeyIDs[0] != "93e4b7f0e28fea87304a68835bce6c71" {
		t.Errorf("Summary.KeyIDs must be 93e4b7f0e28fea87304a68835bce6c71 got %s", pssh.Summary.KeyIDs[0])
	}

}
