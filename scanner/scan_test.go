package scanner

import (
	"context"
	"fmt"
	"testing"
)

func TestCreateResponse(t *testing.T) {
	const (
		TestUUID    = "testUUID"
		TestDataDir = "./testdata"
	)
	var resp []byte
	ctx := context.Background()
	err := createResponse(ctx, TestUUID, TestDataDir, &resp)

	if err != nil {
		fmt.Println("did not work")
	}

	fmt.Println(string(resp))
}

/*
func TestScanImage(t *testing.T) {
	const (
		ImageURL    = "Image2"
		TestDataDir = "./testdata"
	)
	var resp []byte
	err := scanImage(ImageURL, TestDataDir,TestDataDir)

	if err != nil {
		fmt.Println("did not work")
	}

	fmt.Println(string(resp))
}

*/
