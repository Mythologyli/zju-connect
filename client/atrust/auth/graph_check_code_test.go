package auth

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/mythologyli/zju-connect/client/authchallenge"
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

func TestGraphCheckCodeFromResponse(t *testing.T) {
	imgData := buildPNG(t, 300, 150)
	raw, err := graphCheckCodeFromResponse(authchallenge.ClickCaptchaResponse{
		Points: []authchallenge.Point{{X: 11, Y: 22}, {X: 33, Y: 44}},
	}, imgData)
	if err != nil {
		t.Fatal(err)
	}
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Width != 300 || payload.Height != 150 || len(payload.Coordinates) != 2 {
		t.Fatalf("unexpected graph check code payload: %+v", payload)
	}
}

func TestGraphCheckCodeFromResponsePreservesDimensions(t *testing.T) {
	raw, err := graphCheckCodeFromResponse(authchallenge.ClickCaptchaResponse{
		Points: []authchallenge.Point{{X: 11, Y: 22}},
		Width:  640,
		Height: 360,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Width != 640 || payload.Height != 360 {
		t.Fatalf("unexpected graph check code dimensions: %dx%d", payload.Width, payload.Height)
	}
}

func TestGraphCheckCodeFromResponseReplacesIncompleteDimensions(t *testing.T) {
	imgData := buildPNG(t, 300, 150)
	raw, err := graphCheckCodeFromResponse(authchallenge.ClickCaptchaResponse{
		Points: []authchallenge.Point{{X: 11, Y: 22}},
		Width:  640,
	}, imgData)
	if err != nil {
		t.Fatal(err)
	}
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Width != 300 || payload.Height != 150 {
		t.Fatalf("unexpected graph check code dimensions: %dx%d", payload.Width, payload.Height)
	}
}
