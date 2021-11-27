package ping

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_byteSliceOfSize(t *testing.T) {
	n := 2
	slice := byteSliceOfSize(n)

	assert.Equal(t, n, len(slice))
	assert.Equal(t, []byte{1, 1}, slice)
}

func Test_ipv4Payload(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{
			name:  "no header",
			input: []byte{1, 2},
			want:  []byte{1, 2},
		},
		{
			name: "header length 5",
			input: []byte{
				0b00000101, 0, 0, 0, 0,
				1, 1, 1, 1, 1,
				2, 2, 2, 2, 2,
				3, 3, 3, 3, 3,
				4, 4, 4, 4, 4,
			},
			want: []byte{
				4, 4, 4, 4, 4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipv4Payload(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_bytesToTime(t *testing.T) {
	tm := bytesToTime([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	fmt.Println(tm)
}
