package auth

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func buildPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestCanonicalizeGraphCheckCode_ObjectInput(t *testing.T) {
	raw := `{"coordinates":[[11,22],[33,44]],"width":300,"height":150}`
	got, err := canonicalizeGraphCheckCode(raw, nil)
	if err != nil {
		t.Fatalf("canonicalizeGraphCheckCode returned error: %v", err)
	}

	var obj struct {
		Coordinates [][]int `json:"coordinates"`
		Width       int     `json:"width"`
		Height      int     `json:"height"`
	}
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("result is not valid json: %v", err)
	}
	if len(obj.Coordinates) != 2 || len(obj.Coordinates[0]) != 2 || len(obj.Coordinates[1]) != 2 {
		t.Fatalf("unexpected coordinates: %+v", obj.Coordinates)
	}
	if obj.Coordinates[0][0] != 11 || obj.Coordinates[0][1] != 22 || obj.Coordinates[1][0] != 33 || obj.Coordinates[1][1] != 44 {
		t.Fatalf("unexpected coordinates values: %+v", obj.Coordinates)
	}
	if obj.Width != 300 || obj.Height != 150 {
		t.Fatalf("unexpected size: %dx%d", obj.Width, obj.Height)
	}
}

func TestCanonicalizeGraphCheckCode_ArrayObjectInput(t *testing.T) {
	raw := `[{"x":100,"y":200},{"x":150,"y":300}]`
	imgData := buildPNG(t, 320, 180)
	got, err := canonicalizeGraphCheckCode(raw, imgData)
	if err != nil {
		t.Fatalf("canonicalizeGraphCheckCode returned error: %v", err)
	}

	var obj struct {
		Coordinates [][]int `json:"coordinates"`
		Width       int     `json:"width"`
		Height      int     `json:"height"`
	}
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("result is not valid json: %v", err)
	}
	if len(obj.Coordinates) != 2 {
		t.Fatalf("unexpected coordinates length: %d", len(obj.Coordinates))
	}
	if obj.Coordinates[0][0] != 100 || obj.Coordinates[0][1] != 200 || obj.Coordinates[1][0] != 150 || obj.Coordinates[1][1] != 300 {
		t.Fatalf("unexpected coordinates values: %+v", obj.Coordinates)
	}
	if obj.Width != 320 || obj.Height != 180 {
		t.Fatalf("unexpected size: %dx%d", obj.Width, obj.Height)
	}
}

func TestCanonicalizeGraphCheckCode_InvalidInput(t *testing.T) {
	_, err := canonicalizeGraphCheckCode(`{"coordinates":"bad"}`, nil)
	if err == nil {
		t.Fatal("expected error for invalid graph check code input, got nil")
	}
}
