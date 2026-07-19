package spnego

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"reflect"

	"testing"
)

var testEncodeNegTokenInit = []struct {
	Types    []asn1.ObjectIdentifier
	Token    string
	Expected string
}{
	{
		[]asn1.ObjectIdentifier{NlmpOid},
		"4e544c4d5353500001000000978208e2000000000000000000000000000000000a005a290000000f",
		"604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a005a290000000f",
	},
}

func TestEncodeNegTokenInit(t *testing.T) {
	for i, e := range testEncodeNegTokenInit {
		tok, err := hex.DecodeString(e.Token)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := hex.DecodeString(e.Expected)
		if err != nil {
			t.Fatal(err)
		}
		ret, err := EncodeNegTokenInit(e.Types, tok)
		if err != nil {
			t.Errorf("%d: %v\n", i, err)
		}
		if !bytes.Equal(ret, expected) {
			t.Errorf("%d: fail\n", i)
		}
	}
}

var testDecodeNegTokenResp = []struct {
	Input                 string
	ExpectedResponseToken string
	Expected              *NegTokenResp
}{
	{
		"a181ca3081c7a0030a0101a10c060a2b06010401823702020aa281b10481ae4e544c4d5353500002000000100010003800000035828962a9d9c92cf4152e98000000000000000066006600480000000601b01d0f000000460041004b004500520055004e00450001001000460041004b004500520055004e00450002001000460041004b004500520055004e00450003001c00660061006b006500720075006e0065002e006c006f00630061006c0004000a006c006f00630061006c00070008000076b91516c2d10100000000",
		"4e544c4d5353500002000000100010003800000035828962a9d9c92cf4152e98000000000000000066006600480000000601b01d0f000000460041004b004500520055004e00450001001000460041004b004500520055004e00450002001000460041004b004500520055004e00450003001c00660061006b006500720075006e0065002e006c006f00630061006c0004000a006c006f00630061006c00070008000076b91516c2d10100000000",
		&NegTokenResp{
			NegState:      1,
			SupportedMech: NlmpOid,
			MechListMIC:   nil,
		},
	},
	{
		"a1073005a0030a0100",
		"",
		&NegTokenResp{
			NegState: 0,
		},
	},
	{
		"a182000b30820007a08200030a0100", // ber encoding (see https://github.com/hirochachacha/go-smb2/pull/34)
		"",
		&NegTokenResp{
			NegState: 0,
		},
	},
}

func TestDecodeNegTokenResp(t *testing.T) {
	for i, e := range testDecodeNegTokenResp {
		input, err := hex.DecodeString(e.Input)
		if err != nil {
			t.Fatal(err)
		}
		responseToken, err := hex.DecodeString(e.ExpectedResponseToken)
		if err != nil {
			t.Fatal(err)
		}
		if len(responseToken) > 0 {
			e.Expected.ResponseToken = responseToken
		}

		ret, err := DecodeNegTokenResp(input)
		if err != nil {
			t.Errorf("%d: %v\n", i, err)
			continue
		}
		if !reflect.DeepEqual(ret, e.Expected) {
			t.Errorf("%d: fail, expected %v, got %v\n", i, e.Expected, ret)
		}
	}
}

var testEncodeNegTokenResp = []struct {
	Type        asn1.ObjectIdentifier
	Token       string
	MechListMIC string
	Expected    string
}{
	{
		nil,
		"4e544c4d535350000300000018001800ac0000000e010e01c4000000200020005800000026002600780000000e000e009e00000010001000d2010000158288620a005a290000000f3e3d42661105d1439dee00f836cad4fa4d006900630072006f0073006f00660074004100630063006f0075006e0074006800690072006f00650069006b006f0040006f00750074006c006f006f006b002e006a00700048004f004d0045002d0050004300000000000000000000000000000000000000000000000000bf302e94f761de33288f11866a37b29c01010000000000000076b91516c2d1012753c10d333a7b100000000001001000460041004b004500520055004e00450002001000460041004b004500520055004e00450003001c00660061006b006500720075006e0065002e006c006f00630061006c0004000a006c006f00630061006c00070008000076b91516c2d10106000400020000000800300030000000000000000100000000200000052b42bd2cfdf105bc038de93d80375c47f43366bb9376579cf2e7ffcfd06aaf0a001000000000000000000000000000000000000900200063006900660073002f003100390032002e003100360038002e0030002e003700000000000000000000000000849ee9fcd70ea92c0c4f60e0dfaaf6d2",
		"0100000069e24981b5dac33f00000000",
		"a182020730820203a0030a0101a28201e6048201e24e544c4d535350000300000018001800ac0000000e010e01c4000000200020005800000026002600780000000e000e009e00000010001000d2010000158288620a005a290000000f3e3d42661105d1439dee00f836cad4fa4d006900630072006f0073006f00660074004100630063006f0075006e0074006800690072006f00650069006b006f0040006f00750074006c006f006f006b002e006a00700048004f004d0045002d0050004300000000000000000000000000000000000000000000000000bf302e94f761de33288f11866a37b29c01010000000000000076b91516c2d1012753c10d333a7b100000000001001000460041004b004500520055004e00450002001000460041004b004500520055004e00450003001c00660061006b006500720075006e0065002e006c006f00630061006c0004000a006c006f00630061006c00070008000076b91516c2d10106000400020000000800300030000000000000000100000000200000052b42bd2cfdf105bc038de93d80375c47f43366bb9376579cf2e7ffcfd06aaf0a001000000000000000000000000000000000000900200063006900660073002f003100390032002e003100360038002e0030002e003700000000000000000000000000849ee9fcd70ea92c0c4f60e0dfaaf6d2a31204100100000069e24981b5dac33f00000000",
	},
}

func TestEncodeNegTokenResp(t *testing.T) {
	for i, e := range testEncodeNegTokenResp {
		token, err := hex.DecodeString(e.Token)
		if err != nil {
			t.Fatal(err)
		}
		mechListMIC, err := hex.DecodeString(e.MechListMIC)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := hex.DecodeString(e.Expected)
		if err != nil {
			t.Fatal(err)
		}

		ret, err := EncodeNegTokenResp(1, e.Type, token, mechListMIC)
		if err != nil {
			t.Errorf("%d: %v\n", i, err)
		}
		if !bytes.Equal(ret, expected) {
			t.Errorf("%d: fail\n", i)
		}
	}
}

func TestEncodeNegTokenInit2(t *testing.T) {
	tests := []struct {
		name    string
		types   []asn1.ObjectIdentifier
		wantErr bool
	}{
		{
			name:    "encode with NTLM OID",
			types:   []asn1.ObjectIdentifier{NlmpOid},
			wantErr: false,
		},
		{
			name:    "encode with multiple OIDs",
			types:   []asn1.ObjectIdentifier{KerberosOid, NlmpOid},
			wantErr: false,
		},
		{
			name:    "encode with MsKerberos OID",
			types:   []asn1.ObjectIdentifier{MsKerberosOid},
			wantErr: false,
		},
		{
			name:    "encode with empty OID list",
			types:   []asn1.ObjectIdentifier{},
			wantErr: false,
		},
		{
			name:    "encode with nil OID list",
			types:   nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := EncodeNegTokenInit2(tt.types)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeNegTokenInit2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(ret) == 0 {
					t.Errorf("EncodeNegTokenInit2() returned empty result")
				}
				if ret[0] != 0x60 {
					t.Errorf("EncodeNegTokenInit2() first byte = 0x%x, want 0x60", ret[0])
				}
			}
		})
	}
}

func TestDecodeNegTokenInit2(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantOIDs int
	}{
		{
			name:     "decode valid NegTokenInit2 with NTLM",
			input:    "6048" + "06062b0601050502" + "a03e303c" + "a00e300c" + "060a2b06010401823702020a" + "a32a3028a0261b246e6f745f646566696e65645f696e5f52464334313738407" + "06c656173655f69676e6f7265",
			wantErr:  false,
			wantOIDs: 1,
		},
		{
			name:     "decode with malformed ASN.1",
			input:    "60",
			wantErr:  true,
			wantOIDs: 0,
		},
		{
			name:     "decode with invalid tag",
			input:    "7048" + "06062b0601050502" + "a03e303c" + "a00e300c" + "060a2b06010401823702020a",
			wantErr:  true,
			wantOIDs: 0,
		},
		{
			name:     "decode empty input",
			input:    "",
			wantErr:  true,
			wantOIDs: 0,
		},
		{
			name:     "decode truncated data",
			input:    "604806062b06",
			wantErr:  true,
			wantOIDs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatal(err)
			}

			ret, err := DecodeNegTokenInit2(input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeNegTokenInit2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if ret == nil {
					t.Errorf("DecodeNegTokenInit2() returned nil")
					return
				}
				if len(ret.MechTypes) != tt.wantOIDs {
					t.Errorf("DecodeNegTokenInit2() MechTypes length = %d, want %d", len(ret.MechTypes), tt.wantOIDs)
				}
			}
		})
	}
}

func TestEncodeDecodeNegTokenInit2RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		types []asn1.ObjectIdentifier
	}{
		{
			name:  "round trip with NTLM",
			types: []asn1.ObjectIdentifier{NlmpOid},
		},
		{
			name:  "round trip with Kerberos",
			types: []asn1.ObjectIdentifier{KerberosOid},
		},
		{
			name:  "round trip with multiple OIDs",
			types: []asn1.ObjectIdentifier{KerberosOid, NlmpOid},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeNegTokenInit2(tt.types)
			if err != nil {
				t.Fatalf("EncodeNegTokenInit2() error = %v", err)
			}

			decoded, err := DecodeNegTokenInit2(encoded)
			if err != nil {
				t.Fatalf("DecodeNegTokenInit2() error = %v", err)
			}

			if !reflect.DeepEqual(decoded.MechTypes, tt.types) {
				t.Errorf("Round trip failed: got %v, want %v", decoded.MechTypes, tt.types)
			}
		})
	}
}

func TestDecodeNegTokenInit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantOIDs int
	}{
		{
			name:     "decode valid NegTokenInit",
			input:    "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a005a290000000f",
			wantErr:  false,
			wantOIDs: 1,
		},
		{
			name:     "decode with malformed ASN.1",
			input:    "60",
			wantErr:  true,
			wantOIDs: 0,
		},
		{
			name:     "decode with invalid tag",
			input:    "7048" + "06062b0601050502" + "a03e303c" + "a00e300c" + "060a2b06010401823702020a",
			wantErr:  true,
			wantOIDs: 0,
		},
		{
			name:     "decode empty input",
			input:    "",
			wantErr:  true,
			wantOIDs: 0,
		},
		{
			name:     "decode truncated data",
			input:    "604806062b06",
			wantErr:  true,
			wantOIDs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatal(err)
			}

			ret, err := DecodeNegTokenInit(input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeNegTokenInit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if ret == nil {
					t.Errorf("DecodeNegTokenInit() returned nil")
					return
				}
				if len(ret.MechTypes) != tt.wantOIDs {
					t.Errorf("DecodeNegTokenInit() MechTypes length = %d, want %d", len(ret.MechTypes), tt.wantOIDs)
				}
			}
		})
	}
}

func TestEncodeDecodeNegTokenInitRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		types []asn1.ObjectIdentifier
		token []byte
	}{
		{
			name:  "round trip with NTLM and token",
			types: []asn1.ObjectIdentifier{NlmpOid},
			token: []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00},
		},
		{
			name:  "round trip with Kerberos and token",
			types: []asn1.ObjectIdentifier{KerberosOid},
			token: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name:  "round trip with empty token",
			types: []asn1.ObjectIdentifier{NlmpOid},
			token: []byte{},
		},
		{
			name:  "round trip with nil token",
			types: []asn1.ObjectIdentifier{NlmpOid},
			token: nil,
		},
		{
			name:  "round trip with multiple OIDs",
			types: []asn1.ObjectIdentifier{KerberosOid, NlmpOid},
			token: []byte{0x01, 0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeNegTokenInit(tt.types, tt.token)
			if err != nil {
				t.Fatalf("EncodeNegTokenInit() error = %v", err)
			}

			decoded, err := DecodeNegTokenInit(encoded)
			if err != nil {
				t.Fatalf("DecodeNegTokenInit() error = %v", err)
			}

			if !reflect.DeepEqual(decoded.MechTypes, tt.types) {
				t.Errorf("Round trip MechTypes: got %v, want %v", decoded.MechTypes, tt.types)
			}

			if !bytes.Equal(decoded.MechToken, tt.token) {
				t.Errorf("Round trip MechToken: got %v, want %v", decoded.MechToken, tt.token)
			}
		})
	}
}

func TestEncodeNegTokenInitEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		types   []asn1.ObjectIdentifier
		token   []byte
		wantErr bool
	}{
		{
			name:    "empty OID list",
			types:   []asn1.ObjectIdentifier{},
			token:   []byte{0x01, 0x02},
			wantErr: false,
		},
		{
			name:    "nil OID list",
			types:   nil,
			token:   []byte{0x01, 0x02},
			wantErr: false,
		},
		{
			name:    "large token",
			types:   []asn1.ObjectIdentifier{NlmpOid},
			token:   make([]byte, 1024),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := EncodeNegTokenInit(tt.types, tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeNegTokenInit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(ret) == 0 {
					t.Errorf("EncodeNegTokenInit() returned empty result")
				}
				if ret[0] != 0x60 {
					t.Errorf("EncodeNegTokenInit() first byte = 0x%x, want 0x60", ret[0])
				}
			}
		})
	}
}

func TestEncodeNegTokenRespEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		state       asn1.Enumerated
		typ         asn1.ObjectIdentifier
		token       []byte
		mechListMIC []byte
		wantErr     bool
	}{
		{
			name:        "all fields populated",
			state:       1,
			typ:         NlmpOid,
			token:       []byte{0x01, 0x02, 0x03},
			mechListMIC: []byte{0x04, 0x05, 0x06},
			wantErr:     false,
		},
		{
			name:        "minimal fields",
			state:       0,
			typ:         nil,
			token:       nil,
			mechListMIC: nil,
			wantErr:     false,
		},
		{
			name:        "empty token and MIC",
			state:       1,
			typ:         NlmpOid,
			token:       []byte{},
			mechListMIC: []byte{},
			wantErr:     false,
		},
		{
			name:        "large token",
			state:       1,
			typ:         NlmpOid,
			token:       make([]byte, 2048),
			mechListMIC: nil,
			wantErr:     false,
		},
		{
			name:        "different states",
			state:       2,
			typ:         KerberosOid,
			token:       []byte{0x01},
			mechListMIC: nil,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := EncodeNegTokenResp(tt.state, tt.typ, tt.token, tt.mechListMIC)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeNegTokenResp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(ret) == 0 {
				t.Errorf("EncodeNegTokenResp() returned empty result")
			}
		})
	}
}

func TestDecodeNegTokenRespEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "malformed ASN.1 - incomplete tag",
			input:   "a1",
			wantErr: true,
		},
		{
			name:    "malformed ASN.1 - incomplete length",
			input:   "a107",
			wantErr: true,
		},
		{
			name:    "invalid tag",
			input:   "a2073005a0030a0100",
			wantErr: true,
		},
		{
			name:    "truncated sequence",
			input:   "a1073005",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "single byte",
			input:   "00",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatal(err)
			}

			_, err = DecodeNegTokenResp(input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeNegTokenResp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDecodeNegTokenRespRoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		state       asn1.Enumerated
		typ         asn1.ObjectIdentifier
		token       []byte
		mechListMIC []byte
	}{
		{
			name:        "round trip with all fields",
			state:       1,
			typ:         NlmpOid,
			token:       []byte{0x01, 0x02, 0x03, 0x04},
			mechListMIC: []byte{0x05, 0x06, 0x07, 0x08},
		},
		{
			name:        "round trip with minimal fields",
			state:       0,
			typ:         nil,
			token:       nil,
			mechListMIC: nil,
		},
		{
			name:        "round trip with empty slices",
			state:       1,
			typ:         KerberosOid,
			token:       []byte{},
			mechListMIC: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeNegTokenResp(tt.state, tt.typ, tt.token, tt.mechListMIC)
			if err != nil {
				t.Fatalf("EncodeNegTokenResp() error = %v", err)
			}

			decoded, err := DecodeNegTokenResp(encoded)
			if err != nil {
				t.Fatalf("DecodeNegTokenResp() error = %v", err)
			}

			if decoded.NegState != tt.state {
				t.Errorf("Round trip NegState: got %v, want %v", decoded.NegState, tt.state)
			}

			if len(tt.typ) > 0 && !reflect.DeepEqual(decoded.SupportedMech, tt.typ) {
				t.Errorf("Round trip SupportedMech: got %v, want %v", decoded.SupportedMech, tt.typ)
			}

			if len(tt.token) > 0 && !bytes.Equal(decoded.ResponseToken, tt.token) {
				t.Errorf("Round trip ResponseToken: got %v, want %v", decoded.ResponseToken, tt.token)
			}

			if len(tt.mechListMIC) > 0 && !bytes.Equal(decoded.MechListMIC, tt.mechListMIC) {
				t.Errorf("Round trip MechListMIC: got %v, want %v", decoded.MechListMIC, tt.mechListMIC)
			}
		})
	}
}

func TestOIDConstants(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want []int
	}{
		{
			name: "SpnegoOid",
			oid:  SpnegoOid,
			want: []int{1, 3, 6, 1, 5, 5, 2},
		},
		{
			name: "MsKerberosOid",
			oid:  MsKerberosOid,
			want: []int{1, 2, 840, 48018, 1, 2, 2},
		},
		{
			name: "KerberosOid",
			oid:  KerberosOid,
			want: []int{1, 2, 840, 113554, 1, 2, 2},
		},
		{
			name: "NlmpOid",
			oid:  NlmpOid,
			want: []int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual([]int(tt.oid), tt.want) {
				t.Errorf("OID %s = %v, want %v", tt.name, []int(tt.oid), tt.want)
			}
		})
	}
}
