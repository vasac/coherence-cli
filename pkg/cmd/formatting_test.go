/*
 * Copyright (c) 2021, 2023 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"fmt"
	. "github.com/onsi/gomega"
	"testing"
)

func TestCreateCamelCaseLabel(t *testing.T) {
	g := NewGomegaWithT(t)

	g.Expect(CreateCamelCaseLabel("unicastListener")).To(Equal("Unicast Listener"))
	g.Expect(CreateCamelCaseLabel("maxMemoryMB")).To(Equal("Max Memory MB"))
	g.Expect(CreateCamelCaseLabel("nodeId")).To(Equal("Node Id"))
	g.Expect(CreateCamelCaseLabel("UID")).To(Equal("UID"))
	g.Expect(CreateCamelCaseLabel("UUID")).To(Equal("UUID"))
	g.Expect(CreateCamelCaseLabel("multicastTTL")).To(Equal("Multicast TTL"))
	g.Expect(CreateCamelCaseLabel("statusHA")).To(Equal("Status HA"))
	g.Expect(CreateCamelCaseLabel("")).To(Equal(""))
}

func TestFormattingLatency(t *testing.T) {
	g := NewGomegaWithT(t)

	g.Expect(formatLatency(123.333)).To(Equal("123.333ms"))
	g.Expect(formatLatency(1)).To(Equal("1.000ms"))
	g.Expect(formatLatency0(123)).To(Equal("123ms"))
	g.Expect(formatMbps(123.2)).To(Equal("123.2Mbps"))
}

func TestFormatting(t *testing.T) {

	var (
		g        = NewGomegaWithT(t)
		mb int64 = 1024 * 1024
	)

	g.Expect(formatBytesOnly(123)).To(Equal("123"))
	g.Expect(formatBytesOnly(0)).To(Equal("0"))
	g.Expect(formatKBOnly(0)).To(Equal("0 KB"))
	g.Expect(formatKBOnly(1024)).To(Equal("1 KB"))
	g.Expect(formatKBOnly(1000)).To(Equal("0 KB"))
	g.Expect(formatKBOnly(1025)).To(Equal("1 KB"))
	g.Expect(formatKBOnly(13000)).To(Equal("12 KB"))
	g.Expect(formatMBOnly(0)).To(Equal("0 MB"))
	g.Expect(formatMBOnly(10 * mb)).To(Equal("10 MB"))
	g.Expect(formatMBOnly(10*mb - 100)).To(Equal("9 MB"))

	g.Expect(formatGBOnly(0)).To(Equal("0.0 GB"))
	g.Expect(formatGBOnly(123 * mb)).To(Equal("0.1 GB"))
	g.Expect(formatGBOnly(12344 * mb)).To(Equal("12.1 GB"))

}

func TestMax(t *testing.T) {
	g := NewGomegaWithT(t)

	g.Expect(max(123, 124)).To(Equal(int64(124)))
	g.Expect(max(-1, 124)).To(Equal(int64(124)))
}

func TestFormattingPercent(t *testing.T) {
	g := NewGomegaWithT(t)

	g.Expect(formatPercent(.5)).To(Equal("50.00%"))
	g.Expect(formatPercent(-1)).To(Equal("n/a"))
}

func TestFormattingAllStringsWithAlignment(t *testing.T) {
	g := NewGomegaWithT(t)

	table1 := newFormattedTable().WithAlignment(L, R, R).WithHeader("ONE", "TWO", "THREE")
	table1.AddRow("string", "123,200", "100MB")
	table1.AddRow("string", "123", "10MB")
	fmt.Println(table1)

	// test incorrect alignment length which will turn it off
	table2 := newFormattedTable().WithAlignment(L).WithHeader("ONE", "TWO", "THREE")
	table2.AddRow("string", "123,200", "100MB")
	table2.AddRow("string", "123", "10MB")
	fmt.Println(table2)

	g.Expect(table1.String()).To(Equal(`ONE         TWO  THREE
string  123,200  100MB
string      123   10MB
`))

	g.Expect(table2.String()).To(Equal(`ONE     TWO      THREE
string  123,200  100MB
string  123      10MB 
`))
}

// TestFormattingAllStringsWithAlignmentMax1 tests truncated 1st column
func TestFormattingAllStringsWithAlignmentMax1(t *testing.T) {
	g := NewGomegaWithT(t)

	table := newFormattedTable().WithAlignment(L, R, R).WithHeader("ONE", "TWO", "THREE").MaxLength(10)
	table.AddRow("abcdefghijh", "123,200", "100MB")
	table.AddRow("string", "123", "10MB")

	result := table.String()
	fmt.Println(result)
	g.Expect(result).To(Equal(`ONE             TWO  THREE
abcdefg...  123,200  100MB
string          123   10MB
`))
}

// TestFormattingAllStringsWithAlignmentMax2 tests all columns < max
func TestFormattingAllStringsWithAlignmentMax2(t *testing.T) {
	g := NewGomegaWithT(t)

	table := newFormattedTable().WithAlignment(L, R, R).WithHeader("ONE", "TWO", "THREE").MaxLength(10)
	table.AddRow("123", "123,200", "100MB")
	table.AddRow("string", "123", "10MB")

	result := table.String()
	fmt.Println(result)
	g.Expect(result).To(Equal(`ONE         TWO  THREE
123     123,200  100MB
string      123   10MB
`))
}

// TestFormattingAllStringsWithAlignmentMax3 tests all columns truncates
func TestFormattingAllStringsWithAlignmentMax3(t *testing.T) {
	g := NewGomegaWithT(t)

	table := newFormattedTable().WithAlignment(L, L, L).WithHeader("ONE", "TWO", "THREE").MaxLength(10)

	table.AddRow("1this is really long", "1this must be event longer", "1wow how long is this string")
	table.AddRow("2this is really long", "2this must be event longer", "2wow how long is this string")

	result := table.String()
	fmt.Println(result)
	g.Expect(result).To(Equal(`ONE         TWO         THREE     
1this i...  1this m...  1wow ho...
2this i...  2this m...  2wow ho...
`))
}

// TestFormatConnectionMillis tests formatting connection millis
func TestFormatConnectionMillis(t *testing.T) {
	var (
		second int64 = 1000
		minute       = second * 60
		hour         = minute * 60
		day          = hour * 24
		g            = NewGomegaWithT(t)
	)

	g.Expect(formatConnectionMillis(999)).To(Equal("0.9s"))
	g.Expect(formatConnectionMillis(10993)).To(Equal("10.9s"))
	g.Expect(formatConnectionMillis(25 * minute)).To(Equal("25m 00s"))
	g.Expect(formatConnectionMillis(25*minute + second)).To(Equal("25m 01s"))
	g.Expect(formatConnectionMillis(12 * hour)).To(Equal("12h 00m 00s"))
	g.Expect(formatConnectionMillis(12*hour + 2*minute + 1*second)).To(Equal("12h 02m 01s"))
	g.Expect(formatConnectionMillis(3*day + hour)).To(Equal("3d 01h 00m 00s"))
}

func TestTableFormatting(t *testing.T) {
	//g := NewGomegaWithT(t)
	table := newFormattedTable().
		WithHeader("ONE", "TWO", "THREE IS LONG").
		WithAlignment(L, R, R)

	table.AddRow("Hello", "123", "123")

	fmt.Print(table)

	table.AddHeaderColumns("NEW")
	table.AddColumnsToRow("new")

	fmt.Print(table)
}
