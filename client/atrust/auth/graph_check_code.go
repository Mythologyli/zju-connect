package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"
)

type graphCheckCodePayload struct {
	Coordinates [][]int `json:"coordinates"`
	Width       int     `json:"width"`
	Height      int     `json:"height"`
}

type graphCheckCodePoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

func canonicalizeGraphCheckCode(raw string, imgData []byte) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty graph check code")
	}

	if payload, ok := parseGraphCheckCodeObject(trimmed); ok {
		if payload.Width <= 0 || payload.Height <= 0 {
			w, h, err := decodeImageSize(imgData)
			if err != nil {
				return "", fmt.Errorf("graph check code width/height missing and image size unavailable: %w", err)
			}
			payload.Width = w
			payload.Height = h
		}
		return marshalGraphCheckCode(payload)
	}

	if payload, ok := parseGraphCheckCodePointObjectArray(trimmed); ok {
		w, h, err := decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("failed to decode captcha image size: %w", err)
		}
		payload.Width = w
		payload.Height = h
		return marshalGraphCheckCode(payload)
	}

	if payload, ok := parseGraphCheckCodeTupleArray(trimmed); ok {
		w, h, err := decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("failed to decode captcha image size: %w", err)
		}
		payload.Width = w
		payload.Height = h
		return marshalGraphCheckCode(payload)
	}

	return "", fmt.Errorf("unsupported graph check code format")
}

func parseGraphCheckCodeObject(raw string) (graphCheckCodePayload, bool) {
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return graphCheckCodePayload{}, false
	}
	if !isValidCoordinates(payload.Coordinates) {
		return graphCheckCodePayload{}, false
	}
	return payload, true
}

func parseGraphCheckCodePointObjectArray(raw string) (graphCheckCodePayload, bool) {
	var points []graphCheckCodePoint
	if err := json.Unmarshal([]byte(raw), &points); err != nil {
		return graphCheckCodePayload{}, false
	}
	if len(points) == 0 {
		return graphCheckCodePayload{}, false
	}
	coordinates := make([][]int, 0, len(points))
	for _, p := range points {
		coordinates = append(coordinates, []int{p.X, p.Y})
	}
	if !isValidCoordinates(coordinates) {
		return graphCheckCodePayload{}, false
	}
	return graphCheckCodePayload{Coordinates: coordinates}, true
}

func parseGraphCheckCodeTupleArray(raw string) (graphCheckCodePayload, bool) {
	var coordinates [][]int
	if err := json.Unmarshal([]byte(raw), &coordinates); err != nil {
		return graphCheckCodePayload{}, false
	}
	if !isValidCoordinates(coordinates) {
		return graphCheckCodePayload{}, false
	}
	return graphCheckCodePayload{Coordinates: coordinates}, true
}

func isValidCoordinates(coordinates [][]int) bool {
	if len(coordinates) == 0 {
		return false
	}
	for _, pair := range coordinates {
		if len(pair) != 2 {
			return false
		}
	}
	return true
}

func decodeImageSize(imgData []byte) (int, int, error) {
	if len(imgData) == 0 {
		return 0, 0, fmt.Errorf("empty image data")
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(imgData))
	if err != nil {
		return 0, 0, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return 0, 0, fmt.Errorf("invalid image dimensions: %dx%d", cfg.Width, cfg.Height)
	}
	return cfg.Width, cfg.Height, nil
}

func marshalGraphCheckCode(payload graphCheckCodePayload) (string, error) {
	if !isValidCoordinates(payload.Coordinates) {
		return "", fmt.Errorf("invalid coordinates")
	}
	if payload.Width <= 0 || payload.Height <= 0 {
		return "", fmt.Errorf("invalid dimensions: %dx%d", payload.Width, payload.Height)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
