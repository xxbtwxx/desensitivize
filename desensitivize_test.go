package desensitivize

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedact(t *testing.T) {
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
			IntField                  int                 `sensitive:"-"`
			PIntField                 *int                `sensitive:"-"`
			StrField                  string              `sensitive:"-"`
			PStrField                 *string             `sensitive:"-"`
			FloatField                float64             `sensitive:"-"`
			PFloatField               *float64            `sensitive:"-"`
			StructField               StructField         `sensitive:"-"`
			PStructField              *StructField        `sensitive:"-"`
			MapRedact                 map[MapKey]struct{} `sensitive:"-"`
			SliceRedact               []StructField       `sensitive:"-"`
			ArrRedact                 [1]StructField      `sensitive:"-"`
			StructFieldInlineRedact   StructFieldInlineRedact
			PStructFieldInlineRedact  *StructFieldInlineRedact
			PPStructFieldInlineRedact **StructFieldInlineRedact
			StructFieldInlinePRedact  StructFieldInlinePRedact
			PStructFieldInlinePRedact *StructFieldInlinePRedact
			MapFieldInlineRedactKeys  map[MapKey]struct{}
			MapFieldInlinePRedactKeys map[*MapKey]struct{}
			ArrStruct                 []StructField
			ArrPStruct                []*StructField
			PArrStruct                *[]StructField
			PArrPStruct               *[]*StructField
			MapArrayKey               map[[1]MapKey]struct{}
			MapPArrayKey              map[*[1]MapKey]struct{}
			MapPArrayPKey             map[*[1]*MapKey]struct{}
			Array                     [1]MapKey
			PArray                    *[1]MapKey
			PArrayP                   *[1]*MapKey
			ArrayP                    [1]*MapKey
			PMapArrayKey              *map[[1]MapKey]struct{}
			PMapPArrayKey             *map[*[1]MapKey]struct{}
			PMapPArrayPKey            *map[*[1]*MapKey]struct{}
			SliceMapEl                []map[MapKey]struct{}
			PSliceMapEl               *[]map[MapKey]struct{}
			SliceMapElPKey            []map[*MapKey]struct{}
			PSliceMapElPKey           *[]map[*MapKey]struct{}
			MapSliceElem              map[string][]StructFieldInlineRedact
			PMapSliceElem             *map[string][]StructFieldInlineRedact
			MapPSliceElem             map[string]*[]StructFieldInlineRedact
			PMapPSliceElem            *map[string]*[]StructFieldInlineRedact
			MapSlicePElem             map[string][]*StructFieldInlineRedact
			PMapSlicePElem            *map[string][]*StructFieldInlineRedact
			MapPSlicePElem            map[string]*[]*StructFieldInlineRedact
			PMapPSlicePElem           *map[string]*[]*StructFieldInlineRedact
			Arr                       [1]StructFieldInlineRedact
			PArr                      *[1]StructFieldInlineRedact
			ArrP                      [1]*StructFieldInlineRedact
			PArrP                     *[1]*StructFieldInlineRedact
			PPSlice                   **[]StructFieldInlineRedact
			PPSliceP                  **[]*StructFieldInlineRedact
			MapMap                    map[string]map[string]StructFieldInlineRedact
			PMapMap                   *map[string]map[string]StructFieldInlineRedact
			MapPMap                   map[string]*map[string]StructFieldInlineRedact
			PMapPMap                  *map[string]*map[string]StructFieldInlineRedact
			MapMapP                   map[string]map[string]*StructFieldInlineRedact
			PMapMapP                  *map[string]map[string]*StructFieldInlineRedact
			MapPMapP                  map[string]*map[string]*StructFieldInlineRedact
			PMapPMapP                 *map[string]*map[string]*StructFieldInlineRedact
			SliceSlice                [][]StructFieldInlineRedact
			SliceArr                  [][1]StructFieldInlineRedact
			MapArray                  map[string][1]StructFieldInlineRedact
			EmptySlice                []StructFieldInlineRedact
			ArrArr                    [1][1]StructFieldInlineRedact
			ArrSlice                  [1][]StructFieldInlineRedact
			ArrMap                    [1]map[MapKey]StructField
			SlicePPPEl                []***StructFieldInlineRedact
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
		MapArrayKey: map[[1]MapKey]struct{}{
			{{
				F1: "123",
				F3: "321",
			}}: {},
		},
		MapPArrayKey: map[*[1]MapKey]struct{}{
			{{
				F1: "123",
				F3: "321",
			}}: {},
		},
		MapPArrayPKey: map[*[1]*MapKey]struct{}{
			{{
				F1: "123",
				F3: "321",
			}}: {},
		},
		Array: [1]MapKey{{
			F1: "123",
			F3: "321",
		}},
		PArray: vToP([1]MapKey{{
			F1: "123",
			F3: "321",
		}}),
		PArrayP: vToP([1]*MapKey{{
			F1: "123",
			F3: "321",
		}}),
		ArrayP: [1]*MapKey{{
			F1: "123",
			F3: "321",
		}},
		PMapArrayKey: &map[[1]MapKey]struct{}{
			{{
				F1: "123",
				F3: "321",
			}}: {},
		},
		PMapPArrayKey: &map[*[1]MapKey]struct{}{
			{{
				F1: "123",
				F3: "321",
			}}: {},
		},
		PMapPArrayPKey: &map[*[1]*MapKey]struct{}{
			{{
				F1: "123",
				F3: "321",
			}}: {},
		},
		SliceMapEl: []map[MapKey]struct{}{
			{
				MapKey{
					F1: "123",
					F3: "321",
				}: {},
			},
		},
		PSliceMapEl: &[]map[MapKey]struct{}{
			{
				MapKey{
					F1: "123",
					F3: "321",
				}: {},
			},
		},
		SliceMapElPKey: []map[*MapKey]struct{}{
			{
				&MapKey{
					F1: "123",
					F3: "321",
				}: {},
			},
		},
		PSliceMapElPKey: &[]map[*MapKey]struct{}{
			{
				&MapKey{
					F1: "123",
					F3: "321",
				}: {},
			},
		},
		MapSliceElem: map[string][]StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		PMapSliceElem: &map[string][]StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		MapPSliceElem: map[string]*[]StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		PMapPSliceElem: &map[string]*[]StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		MapSlicePElem: map[string][]*StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		PMapSlicePElem: &map[string][]*StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		MapPSlicePElem: map[string]*[]*StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		PMapPSlicePElem: &map[string]*[]*StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		Arr: [1]StructFieldInlineRedact{
			{
				F1: "123",
			},
		},
		PArr: vToP([1]StructFieldInlineRedact{
			{
				F1: "123",
			},
		}),
		ArrP: [1]*StructFieldInlineRedact{
			{
				F1: "123",
			},
		},
		PArrP: vToP([1]*StructFieldInlineRedact{
			{
				F1: "123",
			},
		}),
		PPSlice: vToP(vToP([]StructFieldInlineRedact{
			{
				F1: "123",
			},
		})),

		PPSliceP: vToP(vToP([]*StructFieldInlineRedact{
			{
				F1: "123",
			},
		})),
		PPStructFieldInlineRedact: vToP(&StructFieldInlineRedact{
			F1: "123",
		}),
		MapMap: map[string]map[string]StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		PMapMap: &map[string]map[string]StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		MapPMap: map[string]*map[string]StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		PMapPMap: &map[string]*map[string]StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		MapMapP: map[string]map[string]*StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		PMapMapP: &map[string]map[string]*StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		MapPMapP: map[string]*map[string]*StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		PMapPMapP: &map[string]*map[string]*StructFieldInlineRedact{
			"k": {
				"k": {
					F1: "123",
				},
			},
		},
		MapRedact: map[MapKey]struct{}{
			{
				F1: "123",
			}: {},
		},
		SliceRedact: []StructField{{}},
		ArrRedact:   [1]StructField{{}},
		SliceSlice: [][]StructFieldInlineRedact{
			{
				{
					F1: "123",
				},
			},
		},
		SliceArr: [][1]StructFieldInlineRedact{
			{
				{
					F1: "123",
				},
			},
		},
		MapArray: map[string][1]StructFieldInlineRedact{
			"k": {
				{
					F1: "123",
				},
			},
		},
		ArrArr: [1][1]StructFieldInlineRedact{{
			{
				F1: "123",
			},
		}},
		ArrSlice: [1][]StructFieldInlineRedact{{
			{
				F1: "123",
			},
		}},
		ArrMap: [1]map[MapKey]StructField{
			{
				MapKey{F1: "123"}: {},
			},
		},
		SlicePPPEl: []***StructFieldInlineRedact{vToP(vToP(&StructFieldInlineRedact{
			F1: "123",
		}))},
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
		MapArrayKey: map[[1]MapKey]struct{}{
			{{
				F3: "321",
			}}: {},
		},
		MapPArrayKey: map[*[1]MapKey]struct{}{
			{{
				F3: "321",
			}}: {},
		},
		MapPArrayPKey: map[*[1]*MapKey]struct{}{
			{{
				F3: "321",
			}}: {},
		},
		Array: [1]MapKey{{
			F3: "321",
		}},
		PArray: vToP([1]MapKey{{
			F3: "321",
		}}),
		PArrayP: vToP([1]*MapKey{{
			F3: "321",
		}}),
		ArrayP: [1]*MapKey{{
			F3: "321",
		}},
		PMapArrayKey: &map[[1]MapKey]struct{}{
			{{
				F3: "321",
			}}: {},
		},
		PMapPArrayKey: &map[*[1]MapKey]struct{}{
			{{
				F3: "321",
			}}: {},
		},
		PMapPArrayPKey: &map[*[1]*MapKey]struct{}{
			{{
				F3: "321",
			}}: {},
		},
		SliceMapEl: []map[MapKey]struct{}{
			{
				MapKey{
					F3: "321",
				}: {},
			},
		},
		PSliceMapEl: &[]map[MapKey]struct{}{
			{
				MapKey{
					F3: "321",
				}: {},
			},
		},
		SliceMapElPKey: []map[*MapKey]struct{}{
			{
				&MapKey{
					F3: "321",
				}: {},
			},
		},
		PSliceMapElPKey: &[]map[*MapKey]struct{}{
			{
				&MapKey{
					F3: "321",
				}: {},
			},
		},
		MapSliceElem: map[string][]StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		PMapSliceElem: &map[string][]StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		MapPSliceElem: map[string]*[]StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		PMapPSliceElem: &map[string]*[]StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		MapSlicePElem: map[string][]*StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		PMapSlicePElem: &map[string][]*StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		MapPSlicePElem: map[string]*[]*StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		PMapPSlicePElem: &map[string]*[]*StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		Arr: [1]StructFieldInlineRedact{
			{},
		},
		PArr: vToP([1]StructFieldInlineRedact{
			{},
		}),
		ArrP: [1]*StructFieldInlineRedact{
			{},
		},
		PArrP: vToP([1]*StructFieldInlineRedact{
			{},
		}),
		PPSlice: vToP(vToP([]StructFieldInlineRedact{
			{},
		})),

		PPSliceP: vToP(vToP([]*StructFieldInlineRedact{
			{},
		})),
		PPStructFieldInlineRedact: vToP(&StructFieldInlineRedact{}),
		MapMap: map[string]map[string]StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		PMapMap: &map[string]map[string]StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		MapPMap: map[string]*map[string]StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		PMapPMap: &map[string]*map[string]StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		MapMapP: map[string]map[string]*StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		PMapMapP: &map[string]map[string]*StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		MapPMapP: map[string]*map[string]*StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		PMapPMapP: &map[string]*map[string]*StructFieldInlineRedact{
			"k": {
				"k": {},
			},
		},
		SliceSlice: [][]StructFieldInlineRedact{
			{
				{},
			},
		},
		SliceArr: [][1]StructFieldInlineRedact{
			{
				{},
			},
		},
		MapArray: map[string][1]StructFieldInlineRedact{
			"k": {
				{},
			},
		},
		ArrArr: [1][1]StructFieldInlineRedact{{
			{},
		}},
		ArrSlice: [1][]StructFieldInlineRedact{{
			{},
		}},
		ArrMap: [1]map[MapKey]StructField{
			{
				MapKey{}: {},
			},
		},
		SlicePPPEl: []***StructFieldInlineRedact{vToP(vToP(&StructFieldInlineRedact{}))},
	})
	require.Nil(t, err)

	require.Equal(t, expectedBuf.String(), redactedBuf.String())

	require.Equal(t, testStr, testStrCpy)

	testSlice := []TestStruct{{}}
	Redact(testSlice)
	Redact(&testSlice)
	Redact(vToP(&testSlice))

	testArr := [1]TestStruct{{}}
	Redact(testArr)
	Redact(&testArr)
	Redact(vToP(&testArr))

	testMap := map[string]TestStruct{
		"k": {},
	}
	Redact(testMap)
	Redact(&testMap)
	Redact(vToP(&testMap))

	testP := &TestStruct{}
	Redact(testP)
	Redact(&testP)
	Redact(vToP(&testP))

	testString := ""
	var expected string
	got := Redact(testString)
	require.Equal(t, expected, got)

	gotNew := Redact(&testString)
	require.Equal(t, *gotNew, testString)
}

func vToP[T any](v T) *T {
	return &v
}
