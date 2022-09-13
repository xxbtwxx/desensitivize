package desensitivize

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedact_struct(t *testing.T) {
	type (
		StructField struct {
			F1 string
			F2 int
		}

		StructFieldInlineRedact struct {
			F1 string `sensitive:"-"`
		}

		StructFieldInlinePRedact struct {
			F1 *string `sensitive:"-"`
		}

		MapKey struct {
			F1 string  `sensitive:"-"`
			F2 *string `sensitive:"-"`
			F3 string
		}

		TestStruct struct {
			IntField                  int          `sensitive:"-"`
			PIntField                 *int         `sensitive:"-"`
			StrField                  string       `sensitive:"-"`
			PStrField                 *string      `sensitive:"-"`
			FloatField                float64      `sensitive:"-"`
			PFloatField               *float64     `sensitive:"-"`
			StructField               StructField  `sensitive:"-"`
			PStructField              *StructField `sensitive:"-"`
			StructFieldInlineRedact   StructFieldInlineRedact
			PStructFieldInlineRedact  *StructFieldInlineRedact
			StructFieldInlinePRedact  StructFieldInlinePRedact
			PStructFieldInlinePRedact *StructFieldInlinePRedact
			MapFieldInlineRedactKeys  map[MapKey]struct{}
			MapFieldInlinePRedactKeys map[*MapKey]struct{}
			ArrStruct                 []StructField
			ArrPStruct                []*StructField
			PArrStruct                *[]StructField
			PArrPStruct               *[]*StructField
		}
	)

	testStr := TestStruct{
		IntField:    1,
		PIntField:   vToP(1),
		StrField:    "123",
		PStrField:   vToP("123"),
		FloatField:  1.23,
		PFloatField: vToP(1.23),
		StructField: StructField{
			F1: "321",
			F2: 321,
		},
		PStructField: &StructField{
			F1: "322",
			F2: 322,
		},
		StructFieldInlineRedact: StructFieldInlineRedact{
			F1: "F1",
		},
		PStructFieldInlineRedact: &StructFieldInlineRedact{
			F1: "F11",
		},
		StructFieldInlinePRedact: StructFieldInlinePRedact{
			F1: vToP("12344"),
		},
		PStructFieldInlinePRedact: &StructFieldInlinePRedact{
			F1: vToP("12345"),
		},
		MapFieldInlineRedactKeys: map[MapKey]struct{}{
			{
				F1: "123",
				F2: vToP("123"),
				F3: "321",
			}: {},
		},
		MapFieldInlinePRedactKeys: map[*MapKey]struct{}{
			{
				F1: "123",
				F2: vToP("123"),
				F3: "321",
			}: {},
		},
		ArrStruct:   []StructField{{}},
		ArrPStruct:  []*StructField{{}},
		PArrStruct:  &[]StructField{{}},
		PArrPStruct: &[]*StructField{{}},
	}
	testStrCpy := testStr

	redacted := Redact(testStr)

	var redactedBuf bytes.Buffer
	encRedacted := gob.NewEncoder(&redactedBuf)
	var expectedBuf bytes.Buffer
	encExpected := gob.NewEncoder(&expectedBuf)

	err := encRedacted.Encode(redacted)
	require.Nil(t, err)

	err = encExpected.Encode(TestStruct{
		PStructFieldInlineRedact:  &StructFieldInlineRedact{},
		PStructFieldInlinePRedact: &StructFieldInlinePRedact{},
		MapFieldInlineRedactKeys: map[MapKey]struct{}{
			{F3: "321"}: {},
		},
		MapFieldInlinePRedactKeys: map[*MapKey]struct{}{
			{F3: "321"}: {},
		},
		ArrStruct:   []StructField{{}},
		ArrPStruct:  []*StructField{{}},
		PArrPStruct: &[]*StructField{{}},
		PArrStruct:  &[]StructField{{}},
	})
	require.Nil(t, err)

	require.Equal(t, expectedBuf.String(), redactedBuf.String())

	require.Equal(t, testStr, testStrCpy)
}

func vToP[T any](v T) *T {
	return &v
}
